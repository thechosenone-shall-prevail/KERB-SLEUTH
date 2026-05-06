from pathlib import Path

def main():
    p = Path("pkg/krb/ldap.go")
    t = p.read_text(encoding="utf-8")

    t = t.replace(
        """import (
\t"crypto/tls"
\t"fmt"
\t"log"
\t"net"
\t"strconv"
\t"strings"
\t"time"

\t"github.com/go-ldap/ldap/v3"
\t"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/ingest"
)""",
        """import (
\t"crypto/tls"
\t"crypto/x509"
\t"fmt"
\t"log"
\t"net"
\t"os"
\t"strconv"
\t"strings"
\t"time"

\t"github.com/go-ldap/ldap/v3"
\t"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/ingest"
)""",
        1,
    )

    t = t.replace(
        """type ConnectOptions struct {
\tTarget   string
\tBindUser string
\tBindPass string
\tUseSSL   bool        // LDAPS on port 636
\tStartTLS bool        // Upgrade plaintext on port 389 to TLS
\tInsecure bool        // Skip TLS certificate verification
\tTimeout  time.Duration
}""",
        """type ConnectOptions struct {
\tTarget   string
\tBindUser string
\tBindPass string
\tUseSSL   bool        // LDAPS on port 636
\tStartTLS bool        // Upgrade plaintext on port 389 to TLS
\tInsecure bool        // Skip TLS certificate verification
\tCAFile   string      // PEM CA bundle for TLS (ignored if Insecure)
\tTimeout  time.Duration
\tKDC      string      // Optional explicit Kerberos host
\tGC       string      // Optional Global Catalog host (reserved)
}""",
        1,
    )

    t = t.replace(
        """type LDAPClient struct {
\tconn   *ldap.Conn
\tbaseDN string
}""",
        """type LDAPClient struct {
\tconn        *ldap.Conn
\tbaseDN      string
\tldapHost    string
\tbindSAM     string
\tbindPass    string
\tkdcOverride string
}""",
        1,
    )

    t = t.replace(
        """\tif !opts.Insecure {
\t\ttlsConfig.ServerName = host
\t}

\tvar conn *ldap.Conn""",
        """\tif !opts.Insecure {
\t\ttlsConfig.ServerName = host
\t}
\tif opts.CAFile != "" && !opts.Insecure {
\t\tpemData, err := os.ReadFile(opts.CAFile)
\t\tif err != nil {
\t\t\treturn nil, fmt.Errorf("read CA file %%s: %%w", opts.CAFile, err)
\t\t}
\t\tpool := x509.NewCertPool()
\t\tif !pool.AppendCertsFromPEM(pemData) {
\t\t\treturn nil, fmt.Errorf("no PEM certificates found in %%s", opts.CAFile)
\t\t}
\t\ttlsConfig.RootCAs = pool
\t}

\tvar conn *ldap.Conn""",
        1,
    )
    # fix escaped percent for fmt.Errorf
    t = t.replace('fmt.Errorf("read CA file %%s: %%w"', 'fmt.Errorf("read CA file %s: %w"')
    t = t.replace('fmt.Errorf("no PEM certificates found in %%s"', 'fmt.Errorf("no PEM certificates found in %s"')

    t = t.replace(
        """\treturn &LDAPClient{
\t\tconn:   conn,
\t\tbaseDN: baseDN,
\t}, nil""",
        """\treturn &LDAPClient{
\t\tconn:        conn,
\t\tbaseDN:      baseDN,
\t\tldapHost:    host,
\t\tbindSAM:     SAMAccountNameFromBind(opts.BindUser),
\t\tbindPass:    opts.BindPass,
\t\tkdcOverride: strings.TrimSpace(opts.KDC),
\t}, nil""",
        1,
    )

    t = t.replace(
        '\t\t"lastLogon",\n\t\t"memberOf",',
        '\t\t"lastLogon",\n\t\t"lastLogonTimestamp",\n\t\t"memberOf",',
        1,
    )

    t = t.replace(
        """\t\tuser.PwdLastSet = parseWindowsTimestamp(entry.GetAttributeValue("pwdLastSet"))
\t\tuser.LastLogon = parseWindowsTimestamp(entry.GetAttributeValue("lastLogon"))

\t\t// Store raw fields for debugging""",
        """\t\tuser.PwdLastSet = parseWindowsTimestamp(entry.GetAttributeValue("pwdLastSet"))
\t\tuser.LastLogon = parseWindowsTimestamp(entry.GetAttributeValue("lastLogon"))
\t\tuser.LastLogonTimestamp = parseWindowsTimestamp(entry.GetAttributeValue("lastLogonTimestamp"))

\t\t// Store raw fields for debugging""",
        1,
    )

    t = t.replace(
        """func (c *LDAPClient) GetBaseDN() string {
\treturn c.baseDN
}

// DomainInfo holds basic domain information""",
        """func (c *LDAPClient) GetBaseDN() string {
\treturn c.baseDN
}

// LDAPHost returns the host used for the LDAP connection (KDC fallback).
func (c *LDAPClient) LDAPHost() string {
\treturn c.ldapHost
}

// SearchSubtreePaged runs a whole-subtree search with Simple Paged Results.
func (c *LDAPClient) SearchSubtreePaged(filter string, attributes []string, pageSize uint32) ([]*ldap.Entry, error) {
\tif c.conn == nil {
\t\treturn nil, fmt.Errorf("ldap: no connection")
\t}
\tif pageSize == 0 {
\t\tpageSize = 500
\t}
\treq := ldap.NewSearchRequest(
\t\tc.baseDN,
\t\tldap.ScopeWholeSubtree,
\t\tldap.NeverDerefAliases,
\t\t0, 0, false,
\t\tfilter,
\t\tattributes,
\t\tnil,
\t)
\tsr, err := c.conn.SearchWithPaging(req, pageSize)
\tif err != nil {
\t\treturn nil, err
\t}
\treturn sr.Entries, nil
}

// DomainInfo holds basic domain information""",
        1,
    )

    t = t.replace(
        "hash, err := extractRealASREPHash(username, domain, domainInfo)",
        "hash, err := c.extractRealASREPHash(username, domain, domainInfo)",
        1,
    )
    t = t.replace(
        "hash, err := extractRealKerberoastHash(username, domain, spn, domainInfo)",
        "hash, err := c.extractRealKerberoastHash(username, domain, spn, domainInfo)",
        1,
    )

    oldk = """// --- Kerberos Protocol Helpers (used by hash extraction) ---

func extractRealASREPHash(username, domain string, domainInfo *DomainInfo) (string, error) {
\tkdcAddress := domainInfo.DNSHostName
\tif kdcAddress == "" {
\t\tkdcAddress = fmt.Sprintf("_kerberos._tcp.%s", strings.ToLower(domain))
\t}

\tkerbClient, err := createKerberosClient(domain, kdcAddress)
\tif err != nil {
\t\treturn "", fmt.Errorf("failed to create Kerberos client: %v", err)
\t}

\treturn kerbClient.ExtractASREPHash(username)
}

func extractRealKerberoastHash(username, domain, spn string, domainInfo *DomainInfo) (string, error) {
\tkdcAddress := domainInfo.DNSHostName
\tif kdcAddress == "" {
\t\tkdcAddress = fmt.Sprintf("_kerberos._tcp.%s", strings.ToLower(domain))
\t}

\tkerbClient, err := createKerberosClient(domain, kdcAddress)
\tif err != nil {
\t\treturn "", fmt.Errorf("failed to create Kerberos client: %v", err)
\t}

\treturn kerbClient.ExtractKerberoastHash(username, spn)
}

func createKerberosClient(domain, kdcAddress string) (KerberosProtocolClient, error) {
\treturn &kerberosClientWrapper{
\t\tdomain:     domain,
\t\tkdcAddress: kdcAddress,
\t}, nil
}"""

    newk = """// --- Kerberos Protocol Helpers (used by hash extraction) ---

func (c *LDAPClient) extractRealASREPHash(username, domain string, domainInfo *DomainInfo) (string, error) {
\trealm := domainInfo.DomainName
\tif realm == "" {
\t\trealm = domain
\t}
\tkdcHost, err := ResolveKDCHost(c.ldapHost, c.kdcOverride, domainInfo.DNSHostName, strings.ToLower(realm))
\tif err != nil {
\t\treturn "", err
\t}
\tkerbClient, err := createKerberosClient(domain, kdcHost, c.bindSAM, c.bindPass)
\tif err != nil {
\t\treturn "", fmt.Errorf("failed to create Kerberos client: %v", err)
\t}
\treturn kerbClient.ExtractASREPHash(username)
}

func (c *LDAPClient) extractRealKerberoastHash(serviceSAM, domain, spn string, domainInfo *DomainInfo) (string, error) {
\tif c.bindSAM == "" || c.bindPass == "" {
\t\treturn "", fmt.Errorf("Kerberoasting requires authenticated LDAP bind credentials (-u/-p)")
\t}
\trealm := domainInfo.DomainName
\tif realm == "" {
\t\trealm = domain
\t}
\tkdcHost, err := ResolveKDCHost(c.ldapHost, c.kdcOverride, domainInfo.DNSHostName, strings.ToLower(realm))
\tif err != nil {
\t\treturn "", err
\t}
\tkerbClient, err := createKerberosClient(domain, kdcHost, c.bindSAM, c.bindPass)
\tif err != nil {
\t\treturn "", fmt.Errorf("failed to create Kerberos client: %v", err)
\t}
\treturn kerbClient.ExtractKerberoastHash(serviceSAM, spn)
}

func createKerberosClient(domain, kdcAddress, clientSAM, clientPass string) (KerberosProtocolClient, error) {
\treturn &kerberosClientWrapper{
\t\tdomain:      domain,
\t\tkdcAddress:  kdcAddress,
\t\tclientSAM:   clientSAM,
\t\tclientPass:  clientPass,
\t}, nil
}"""

    if oldk not in t:
        raise SystemExit("kerberos helper block not found")
    t = t.replace(oldk, newk, 1)

    t = t.replace(
        """type kerberosClientWrapper struct {
\tdomain     string
\tkdcAddress string
\trealClient *RealKerberosClient
}""",
        """type kerberosClientWrapper struct {
\tdomain      string
\tkdcAddress  string
\tclientSAM   string
\tclientPass  string
\trealClient   *RealKerberosClient
}""",
        1,
    )

    t = t.replace(
        """func (k *kerberosClientWrapper) ExtractASREPHash(username string) (string, error) {
\tif k.realClient == nil {
\t\tclient, err := NewRealKerberosClient(k.domain, k.kdcAddress)
\t\tif err != nil {
\t\t\treturn "", err
\t\t}
\t\tk.realClient = client
\t}
\treturn k.realClient.ExtractASREPHash(username)
}""",
        """func (k *kerberosClientWrapper) ExtractASREPHash(username string) (string, error) {
\tif k.realClient == nil {
\t\tclient, err := NewRealKerberosClient(k.domain, k.kdcAddress)
\t\tif err != nil {
\t\t\treturn "", err
\t\t}
\t\tclient.SetClientCredentials(k.clientSAM, k.clientPass)
\t\tk.realClient = client
\t}
\treturn k.realClient.ExtractASREPHash(username)
}""",
        1,
    )

    t = t.replace(
        """func (k *kerberosClientWrapper) ExtractKerberoastHash(username, spn string) (string, error) {
\tif k.realClient == nil {
\t\tclient, err := NewRealKerberosClient(k.domain, k.kdcAddress)
\t\tif err != nil {
\t\t\treturn "", err
\t\t}
\t\tk.realClient = client
\t}
\treturn k.realClient.ExtractKerberoastHash(username, spn)
}""",
        """func (k *kerberosClientWrapper) ExtractKerberoastHash(username, spn string) (string, error) {
\tif k.realClient == nil {
\t\tclient, err := NewRealKerberosClient(k.domain, k.kdcAddress)
\t\tif err != nil {
\t\t\treturn "", err
\t\t}
\t\tclient.SetClientCredentials(k.clientSAM, k.clientPass)
\t\tk.realClient = client
\t}
\treturn k.realClient.ExtractKerberoastHash(username, spn)
}""",
        1,
    )

    p.write_text(t, encoding="utf-8")
    print("patched ldap.go")

if __name__ == "__main__":
    main()
