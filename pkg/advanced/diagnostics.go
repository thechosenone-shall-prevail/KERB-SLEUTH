package advanced

import "strings"

// ExplainProtocolError converts raw module errors into operator-friendly diagnosis.
func ExplainProtocolError(module string, err error) string {
	if err == nil {
		return "no error"
	}
	raw := strings.ToLower(err.Error())
	switch strings.ToLower(strings.TrimSpace(module)) {
	case "smb":
		return ExplainSMBError(err)
	case "trust", "ldap_config", "user_attributes", "password_policy", "shadow_credentials", "acl", "gpo", "sessions", "rbcd", "s4u", "pkinit", "dcsync", "laps":
		switch {
		case strings.Contains(raw, "insufficientaccessrights"), strings.Contains(raw, "insufficient access"), strings.Contains(raw, "access denied"), strings.Contains(raw, "00002098"):
			return "LDAP bind succeeded but lacks directory read rights for this attribute/container"
		case strings.Contains(raw, "invalid credentials"), strings.Contains(raw, "ldap result code 49"):
			return "LDAP authentication failed (username/password/domain format issue)"
		case strings.Contains(raw, "no such object"), strings.Contains(raw, "0000208d"):
			return "LDAP base DN/container not found for this query"
		case strings.Contains(raw, "can't contact ldap server"), strings.Contains(raw, "dial tcp"), strings.Contains(raw, "timeout"):
			return "LDAP connectivity issue (network path, DNS, firewall, TLS handshake)"
		default:
			return "unclassified LDAP/module error (check raw module output for failing query/filter)"
		}
	case "dns":
		switch {
		case strings.Contains(raw, "failed to query ns records"), strings.Contains(raw, "no such host"):
			return "DNS resolution failed for domain/NS records"
		case strings.Contains(raw, "refused"):
			return "AXFR refused by nameserver (expected in hardened environments)"
		case strings.Contains(raw, "timeout"):
			return "DNS query/transfer timeout (filtering or unreachable NS)"
		default:
			return "unclassified DNS error (verify domain, NS reachability, and TCP/53)"
		}
	default:
		switch {
		case strings.Contains(raw, "timeout"), strings.Contains(raw, "deadline exceeded"):
			return "operation timed out (target slow, blocked, or unreachable)"
		case strings.Contains(raw, "access denied"), strings.Contains(raw, "permission"):
			return "insufficient privileges for this check"
		default:
			return "unclassified module error (inspect raw error string)"
		}
	}
}
