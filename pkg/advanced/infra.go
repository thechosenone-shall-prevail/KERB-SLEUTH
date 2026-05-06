package advanced

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/miekg/dns"
)

type TrustResult struct {
	TrustName    string `json:"trust_name"`
	TrustType    string `json:"trust_type"`
	Direction    string `json:"direction"`
	IsTransitive bool   `json:"transitive"`
	Partner      string `json:"trust_partner"`
	SID          string `json:"sid,omitempty"`
}

type DNSZoneTransferResult struct {
	Nameserver  string   `json:"nameserver"`
	Zone        string   `json:"zone"`
	RecordCount int      `json:"record_count"`
	Records     []string `json:"records,omitempty"`
	Error       string   `json:"error,omitempty"`
}

type LAPSResult struct {
	Computer string `json:"computer"`
	Password string `json:"password,omitempty"`
	Expires  string `json:"expires,omitempty"`
	Source   string `json:"source"`
	Account  string `json:"account,omitempty"`
	GMSA     bool   `json:"gmsa,omitempty"`
}

type GPOResult struct {
	CN          string   `json:"cn"`
	DisplayName string   `json:"display_name,omitempty"`
	FileSysPath string   `json:"filesystem_path,omitempty"`
	GPOptions   string   `json:"gpo_options,omitempty"`
	Notes       []string `json:"notes,omitempty"`
}

type SessionResult struct {
	SamAccountName     string `json:"sam_account_name"`
	LastLogon          string `json:"last_logon,omitempty"`
	LastLogonTimestamp string `json:"last_logon_timestamp,omitempty"`
	LogonCount         int    `json:"logon_count,omitempty"`
	LikelyActive       bool   `json:"likely_active"`
}

type ACLAnalysisResult struct {
	ObjectDN                 string   `json:"object_dn"`
	ObjectType               string   `json:"object_type"`
	AdminCount               bool     `json:"admin_count"`
	HighPrivilegeMemberships []string `json:"high_privilege_memberships,omitempty"`
	Notes                    []string `json:"notes,omitempty"`
}

func (aa *AdvancedAnalyzer) RunTrustAnalysis() error {
	log.Printf("[*] Starting domain trust analysis...")

	filter := "(|(objectClass=trustedDomain)(objectClass=trustRoot)(objectClass=trustedForest))"
	attrs := []string{"cn", "flatName", "trustType", "trustAttributes", "trustDirection", "trustPartner", "securityIdentifier"}

	entries, err := aa.Client.SearchSubtreePaged(filter, attrs, 500)
	if err != nil {
		return fmt.Errorf("trust enumeration failed: %v", err)
	}

	var trusts []TrustResult
	for _, entry := range entries {
		trusts = append(trusts, TrustResult{
			TrustName:    entry.GetAttributeValue("cn"),
			TrustType:    lookupTrustType(entry.GetAttributeValue("trustType")),
			Direction:    lookupTrustDirection(entry.GetAttributeValue("trustDirection")),
			IsTransitive: strings.Contains(entry.GetAttributeValue("trustAttributes"), "16"),
			Partner:      entry.GetAttributeValue("trustPartner"),
			SID:          entry.GetAttributeValue("securityIdentifier"),
		})
	}

	log.Printf("[+] Found %d configured domain trusts", len(trusts))
	if aa.Results == nil {
		aa.Results = make(map[string]interface{})
	}
	aa.Results["trusts"] = trusts
	return nil
}

func lookupTrustType(value string) string {
	switch value {
	case "1":
		return "Downlevel"
	case "2":
		return "Uplevel"
	case "3":
		return "MIT"
	case "4":
		return "DCE"
	case "8":
		return "Forest"
	case "9":
		return "External"
	default:
		return "Unknown"
	}
}

func lookupTrustDirection(value string) string {
	if value == "0" {
		return "Disabled"
	}
	if strings.Contains(value, "1") && strings.Contains(value, "2") {
		return "Bidirectional"
	}
	if strings.Contains(value, "1") {
		return "Inbound"
	}
	if strings.Contains(value, "2") {
		return "Outbound"
	}
	return "Unknown"
}

func (aa *AdvancedAnalyzer) RunDNSAnalysis() error {
	log.Printf("[*] Starting DNS zone transfer analysis...")
	domain := strings.TrimSpace(strings.ToLower(aa.Domain))
	if domain == "" {
		return fmt.Errorf("domain not available for DNS analysis")
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	client := new(dns.Client)
	resp, _, err := client.Exchange(m, net.JoinHostPort(aa.Target, "53"))
	if err != nil {
		return fmt.Errorf("failed to query NS records: %v", err)
	}

	var results []DNSZoneTransferResult
	for _, ans := range resp.Answer {
		ns, ok := ans.(*dns.NS)
		if !ok {
			continue
		}
		nsHost := strings.TrimSuffix(ns.Ns, ".")
		log.Printf("[*] Attempting AXFR against %s", nsHost)
		xfr := new(dns.Transfer)
		msg := new(dns.Msg)
		msg.SetAxfr(dns.Fqdn(domain))
		channel, err := xfr.In(msg, net.JoinHostPort(nsHost, "53"))
		if err != nil {
			results = append(results, DNSZoneTransferResult{Nameserver: nsHost, Zone: domain, Error: err.Error()})
			continue
		}

		var records []string
		count := 0
		for env := range channel {
			if env.Error != nil {
				results = append(results, DNSZoneTransferResult{Nameserver: nsHost, Zone: domain, Error: env.Error.Error()})
				break
			}
			for _, rr := range env.RR {
				records = append(records, rr.String())
				count++
			}
		}
		results = append(results, DNSZoneTransferResult{Nameserver: nsHost, Zone: domain, RecordCount: count, Records: records})
	}

	if aa.Results == nil {
		aa.Results = make(map[string]interface{})
	}
	aa.Results["dns_transfers"] = results
	return nil
}

func (aa *AdvancedAnalyzer) RunLAPSAnalysis() error {
	log.Printf("[*] Starting LAPS / gMSA enumeration...")

	var results []LAPSResult

	// Find LAPS passwords stored in ms-Mcs-AdmPwd
	entries, err := aa.Client.SearchSubtreePaged("(&(objectClass=computer)(ms-Mcs-AdmPwd=*))", []string{"distinguishedName", "cn", "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime"}, 500)
	if err == nil {
		for _, entry := range entries {
			results = append(results, LAPSResult{
				Computer: entry.GetAttributeValue("cn"),
				Password: entry.GetAttributeValue("ms-Mcs-AdmPwd"),
				Expires:  entry.GetAttributeValue("ms-Mcs-AdmPwdExpirationTime"),
				Source:   entry.GetAttributeValue("distinguishedName"),
			})
		}
	}

	// Enumerate gMSA accounts
	entries, err = aa.Client.SearchSubtreePaged("(objectClass=msDS-GroupManagedServiceAccount)", []string{"distinguishedName", "sAMAccountName", "servicePrincipalName"}, 500)
	if err == nil {
		for _, entry := range entries {
			results = append(results, LAPSResult{
				Account: entry.GetAttributeValue("sAMAccountName"),
				GMSA:    true,
				Source:  entry.GetAttributeValue("distinguishedName"),
			})
		}
	}

	log.Printf("[+] Found %d LAPS/gMSA entries", len(results))
	if aa.Results == nil {
		aa.Results = make(map[string]interface{})
	}
	aa.Results["laps"] = results
	return nil
}

func (aa *AdvancedAnalyzer) RunGPOAnalysis() error {
	log.Printf("[*] Starting Group Policy analysis...")

	base := fmt.Sprintf("CN=Policies,CN=System,%s", aa.Client.GetBaseDN())
	searchRequest := ldap.NewSearchRequest(
		base,
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=groupPolicyContainer)",
		[]string{"cn", "displayName", "gPOptions", "gPCFileSysPath"},
		nil,
	)
	resp, err := aa.Client.GetConnection().Search(searchRequest)
	if err != nil {
		return fmt.Errorf("GPO enumeration failed: %v", err)
	}

	var results []GPOResult
	for _, entry := range resp.Entries {
		notes := []string{}
		if strings.TrimSpace(entry.GetAttributeValue("gPCFileSysPath")) == "" {
			notes = append(notes, "GPO file system path not set")
		}
		if entry.GetAttributeValue("gPOptions") != "0" {
			notes = append(notes, fmt.Sprintf("Non-default gPOptions: %s", entry.GetAttributeValue("gPOptions")))
		}

		results = append(results, GPOResult{
			CN:          entry.GetAttributeValue("cn"),
			DisplayName: entry.GetAttributeValue("displayName"),
			FileSysPath: entry.GetAttributeValue("gPCFileSysPath"),
			GPOptions:   entry.GetAttributeValue("gPOptions"),
			Notes:       notes,
		})
	}

	log.Printf("[+] Found %d group policy containers", len(results))
	if aa.Results == nil {
		aa.Results = make(map[string]interface{})
	}
	aa.Results["gpos"] = results
	return nil
}

func (aa *AdvancedAnalyzer) RunSessionAnalysis() error {
	log.Printf("[*] Starting session enumeration analysis...")

	entries, err := aa.Client.SearchSubtreePaged("(&(objectCategory=person)(objectClass=user))", []string{"sAMAccountName", "lastLogonTimestamp", "lastLogon", "logonCount"}, 500)
	if err != nil {
		return fmt.Errorf("session enumeration failed: %v", err)
	}

	var results []SessionResult
	for _, entry := range entries {
		lastLogon := entry.GetAttributeValue("lastLogon")
		lastLogonTimestamp := entry.GetAttributeValue("lastLogonTimestamp")
		logonCount := parseLDAPInt(entry.GetAttributeValue("logonCount"))
		active := isRecentLogon(lastLogonTimestamp, lastLogon)
		results = append(results, SessionResult{
			SamAccountName:     entry.GetAttributeValue("sAMAccountName"),
			LastLogon:          lastLogon,
			LastLogonTimestamp: lastLogonTimestamp,
			LogonCount:         logonCount,
			LikelyActive:       active,
		})
	}

	log.Printf("[+] Session enumeration completed, %d user entries analyzed", len(results))
	if aa.Results == nil {
		aa.Results = make(map[string]interface{})
	}
	aa.Results["sessions"] = results
	return nil
}

func parseLDAPInt(value string) int {
	if value == "" {
		return 0
	}
	i, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return i
}

func isRecentLogon(timestamp, lastLogon string) bool {
	if t, err := parseWindowsTime(timestamp); err == nil {
		return time.Since(t) < 30*24*time.Hour
	}
	if t, err := parseWindowsTime(lastLogon); err == nil {
		return time.Since(t) < 30*24*time.Hour
	}
	return false
}

func parseWindowsTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, fmt.Errorf("empty time")
	}
	if strings.Contains(value, "-") {
		return time.Parse(time.RFC3339, value)
	}
	i, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	// Windows FILETIME is 100-nanosecond intervals since 1601
	t := time.Unix(0, (i-116444736000000000)*100)
	return t, nil
}

func (aa *AdvancedAnalyzer) RunACLAnalysis() error {
	log.Printf("[*] Starting ACL and privileged object analysis...")

	entries, err := aa.Client.SearchSubtreePaged("(|(adminCount=1)(memberOf=CN=Domain Admins,*)(memberOf=CN=Enterprise Admins,*)(memberOf=CN=Schema Admins,*))", []string{"distinguishedName", "sAMAccountName", "objectClass", "memberOf", "adminCount"}, 500)
	if err != nil {
		return fmt.Errorf("ACL analysis failed: %v", err)
	}

	var results []ACLAnalysisResult
	for _, entry := range entries {
		memberOf := entry.GetAttributeValues("memberOf")
		high := []string{}
		for _, m := range memberOf {
			if strings.Contains(strings.ToLower(m), "domain admins") || strings.Contains(strings.ToLower(m), "enterprise admins") || strings.Contains(strings.ToLower(m), "schema admins") {
				high = append(high, m)
			}
		}

		results = append(results, ACLAnalysisResult{
			ObjectDN:                 entry.DN,
			ObjectType:               strings.Join(entry.GetAttributeValues("objectClass"), ","),
			AdminCount:               entry.GetAttributeValue("adminCount") == "1",
			HighPrivilegeMemberships: high,
			Notes:                    []string{"Objects with administrative marking or membership indicate hardened/privileged ACLs."},
		})
	}

	log.Printf("[+] ACL analysis enumerated %d privileged objects", len(results))
	if aa.Results == nil {
		aa.Results = make(map[string]interface{})
	}
	aa.Results["acl_analysis"] = results
	return nil
}
