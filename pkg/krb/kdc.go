package krb

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// ResolveKDCHost picks a KDC hostname for Kerberos traffic.
// Precedence: explicit manualKDC, then dnsHostName from RootDSE, then ldapHost (LDAP target),
// then DNS SRV for the realm (_kerberos._tcp.dc._msdcs.<realm> then _kerberos._tcp.<realm>).
func ResolveKDCHost(ldapHost, manualKDC, dnsHostName, realm string) (string, error) {
	manualKDC = strings.TrimSpace(manualKDC)
	if manualKDC != "" {
		return hostWithoutPort(manualKDC), nil
	}
	if h := strings.TrimSpace(dnsHostName); h != "" {
		return hostWithoutPort(h), nil
	}
	if h := strings.TrimSpace(ldapHost); h != "" {
		return hostWithoutPort(h), nil
	}
	realm = strings.Trim(strings.TrimSpace(strings.ToLower(realm)), ".")
	if realm == "" {
		return "", fmt.Errorf("cannot resolve KDC: pass --kdc, point LDAP at a DC hostname, or supply a resolvable DNS realm for SRV lookup")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, addrs, err := net.DefaultResolver.LookupSRV(ctx, "kerberos", "tcp", "dc._msdcs."+realm); err == nil && len(addrs) > 0 {
		return strings.TrimSuffix(addrs[0].Target, "."), nil
	}
	if _, addrs, err := net.DefaultResolver.LookupSRV(ctx, "kerberos", "tcp", realm); err == nil && len(addrs) > 0 {
		return strings.TrimSuffix(addrs[0].Target, "."), nil
	}
	return "", fmt.Errorf("DNS SRV lookup for Kerberos failed for realm %q", realm)
}

func hostWithoutPort(host string) string {
	h, _, err := net.SplitHostPort(host)
	if err == nil {
		return h
	}
	return host
}

// SAMAccountNameFromBind returns the sAMAccountName portion of DOMAIN\\user or user@domain binds.
func SAMAccountNameFromBind(bindUser string) string {
	bindUser = strings.TrimSpace(bindUser)
	if bindUser == "" {
		return ""
	}
	if i := strings.LastIndex(bindUser, "\\"); i >= 0 && i+1 < len(bindUser) {
		return bindUser[i+1:]
	}
	if i := strings.LastIndex(bindUser, "@"); i > 0 {
		return bindUser[:i]
	}
	return bindUser
}
