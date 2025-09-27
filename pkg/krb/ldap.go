package krb

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/yourusername/kerb-sleuth/pkg/ingest"
)

// LDAPClient wraps LDAP connection for AD enumeration
type LDAPClient struct {
	conn   *ldap.Conn
	baseDN string
}

// ConnectLDAP establishes LDAP connection to domain controller
func ConnectLDAP(target, bindUser, bindPass string, useSSL bool) (*LDAPClient, error) {
	var conn *ldap.Conn
	var err error
	var port int

	// Determine port and connection type
	if useSSL {
		port = 636
		if !strings.Contains(target, ":") {
			target = fmt.Sprintf("%s:%d", target, port)
		}
		
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true, // For testing - should be configurable in production
		}
		conn, err = ldap.DialTLS("tcp", target, tlsConfig)
	} else {
		port = 389
		if !strings.Contains(target, ":") {
			target = fmt.Sprintf("%s:%d", target, port)
		}
		conn, err = ldap.Dial("tcp", target)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %v", target, err)
	}

	// Attempt to bind
	if bindUser != "" && bindPass != "" {
		err = conn.Bind(bindUser, bindPass)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to bind as %s: %v", bindUser, err)
		}
	} else {
		// Anonymous bind
		err = conn.UnauthenticatedBind("")
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to perform anonymous bind: %v", err)
		}
	}

	// Determine base DN by querying root DSE
	baseDN, err := getBaseDN(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to determine base DN: %v", err)
	}

	log.Printf("Connected to %s, Base DN: %s", target, baseDN)

	return &LDAPClient{
		conn:   conn,
		baseDN: baseDN,
	}, nil
}

// ConnectToTarget attempts to connect to a target DC with various methods
func ConnectToTarget(target string) (*LDAPClient, error) {
	log.Printf("Attempting to connect to target: %s", target)

	// Try to resolve target to IP if it's a hostname
	ips, err := net.LookupIP(target)
	if err != nil {
		log.Printf("Failed to resolve %s: %v", target, err)
	} else {
		log.Printf("Resolved %s to: %v", target, ips)
	}

	// Try different connection methods in order of preference
	connectionMethods := []struct {
		name     string
		target   string
		bindUser string
		bindPass string
		useSSL   bool
	}{
		{"Anonymous LDAP", target, "", "", false},
		{"Anonymous LDAPS", target, "", "", true},
	}

	for _, method := range connectionMethods {
		log.Printf("Trying %s connection to %s", method.name, method.target)
		
		client, err := ConnectLDAP(method.target, method.bindUser, method.bindPass, method.useSSL)
		if err != nil {
			log.Printf("%s failed: %v", method.name, err)
			continue
		}
		
		log.Printf("Successfully connected using %s", method.name)
		return client, nil
	}

	return nil, fmt.Errorf("all connection attempts failed")
}

// EnumerateUsers performs live user enumeration
func (c *LDAPClient) EnumerateUsers() ([]ingest.User, error) {
	log.Println("Enumerating users...")
	
	searchFilter := "(&(objectCategory=person)(objectClass=user))"
	attributes := []string{
		"sAMAccountName",
		"distinguishedName", 
		"userAccountControl",
		"servicePrincipalName",
		"pwdLastSet",
		"lastLogon",
		"memberOf",
		"description",
		"mail",
	}

	searchRequest := ldap.NewSearchRequest(
		c.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, // size limit (0 = no limit)
		0, // time limit (0 = no limit)
		false,
		searchFilter,
		attributes,
		nil,
	)

	sr, err := c.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %v", err)
	}

	log.Printf("Found %d user objects", len(sr.Entries))

	var users []ingest.User
	for _, entry := range sr.Entries {
		user := ingest.User{
			SamAccountName:        entry.GetAttributeValue("sAMAccountName"),
			DistinguishedName:     entry.GetAttributeValue("distinguishedName"),
			ServicePrincipalNames: entry.GetAttributeValues("servicePrincipalName"),
			MemberOf:              entry.GetAttributeValues("memberOf"),
			RawFields:             make(map[string]string),
		}

		// Parse userAccountControl
		uacStr := entry.GetAttributeValue("userAccountControl")
		if uacStr != "" {
			if uac, err := strconv.Atoi(uacStr); err == nil {
				user.UserAccountControl = uac
				// Check for DONT_REQ_PREAUTH flag (0x400000)
				user.DoesNotRequirePreAuth = (uac & 0x400000) != 0
			}
		}

		// Parse timestamps
		user.PwdLastSet = parseWindowsTimestamp(entry.GetAttributeValue("pwdLastSet"))
		user.LastLogon = parseWindowsTimestamp(entry.GetAttributeValue("lastLogon"))

		// Store raw fields for debugging
		for _, attr := range entry.Attributes {
			if len(attr.Values) > 0 {
				user.RawFields[attr.Name] = strings.Join(attr.Values, ";")
			}
		}

		users = append(users, user)
	}

	return users, nil
}

// GetDomainInfo retrieves basic domain information
func (c *LDAPClient) GetDomainInfo() (*DomainInfo, error) {
	log.Println("Gathering domain information...")

	// Get domain root
	searchRequest := ldap.NewSearchRequest(
		c.baseDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"distinguishedName", "dnsHostName", "ldapServiceName", "domainFunctionality"},
		nil,
	)

	sr, err := c.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get domain info: %v", err)
	}

	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("no domain information found")
	}

	entry := sr.Entries[0]
	info := &DomainInfo{
		BaseDN:       c.baseDN,
		DNSHostName:  entry.GetAttributeValue("dnsHostName"),
		LDAPService:  entry.GetAttributeValue("ldapServiceName"),
	}

	// Extract domain name from base DN
	info.DomainName = strings.ToUpper(strings.ReplaceAll(
		strings.ReplaceAll(c.baseDN, "DC=", ""), ",", "."))

	return info, nil
}

// Close closes the LDAP connection
func (c *LDAPClient) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

// Helper functions

func getBaseDN(conn *ldap.Conn) (string, error) {
	searchRequest := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"defaultNamingContext"},
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		return "", err
	}

	if len(sr.Entries) == 0 || len(sr.Entries[0].Attributes) == 0 {
		return "", fmt.Errorf("could not determine base DN")
	}

	return sr.Entries[0].GetAttributeValue("defaultNamingContext"), nil
}

func parseWindowsTimestamp(timestamp string) time.Time {
	if timestamp == "" || timestamp == "0" {
		return time.Time{}
	}
	
	// Windows timestamp is 100-nanosecond intervals since 1601-01-01
	if ts, err := strconv.ParseInt(timestamp, 10, 64); err == nil {
		// Convert to Unix timestamp
		windowsEpoch := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
		return windowsEpoch.Add(time.Duration(ts) * 100 * time.Nanosecond)
	}
	return time.Time{}
}

// DomainInfo holds basic domain information
type DomainInfo struct {
	BaseDN      string
	DomainName  string
	DNSHostName string
	LDAPService string
}
