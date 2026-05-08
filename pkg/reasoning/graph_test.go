package reasoning

import (
	"testing"
	"time"

	"github.com/thechosenone-shall-prevail/cold-relay/pkg/advanced"
	"github.com/thechosenone-shall-prevail/cold-relay/pkg/ingest"
	"github.com/thechosenone-shall-prevail/cold-relay/pkg/krb"
)

func TestAnnotateCandidates(t *testing.T) {
	candidates := []krb.Candidate{
		{SamAccountName: "svc_sql", Type: "KERBEROAST", SPNs: []string{"MSSQLSvc/sql.local"}},
		{SamAccountName: "asrep_user", Type: "ASREP", Hash: "$krb5asrep$23$user@REALM:abcd"},
		{SamAccountName: "Administrator", Type: "HVT"},
	}

	annotated := AnnotateCandidates(candidates)

	if annotated[0].Validation != krb.StatusTheoretical {
		t.Fatalf("expected kerberoast without hash to be theoretical, got %q", annotated[0].Validation)
	}
	if len(annotated[0].Blockers) == 0 {
		t.Fatal("expected unvalidated kerberoast candidate to include blockers")
	}
	if annotated[1].Validation != krb.StatusValidated {
		t.Fatalf("expected ASREP with hash to be validated, got %q", annotated[1].Validation)
	}
	if annotated[2].Validation != krb.StatusLikely {
		t.Fatalf("expected HVT membership finding to be likely, got %q", annotated[2].Validation)
	}
}

func TestBuildGraphConnectsCoreObjects(t *testing.T) {
	users := []ingest.User{
		{
			SamAccountName:        "svc_sql",
			UserAccountControl:    512,
			ServicePrincipalNames: []string{"MSSQLSvc/sql.logging.htb:1433"},
			MemberOf:              []string{"CN=Service Accounts,DC=logging,DC=htb"},
		},
		{
			SamAccountName: "Administrator",
			MemberOf:       []string{"CN=Domain Admins,DC=logging,DC=htb"},
		},
	}
	candidates := AnnotateCandidates([]krb.Candidate{
		{SamAccountName: "svc_sql", Type: "KERBEROAST", SPNs: []string{"MSSQLSvc/sql.logging.htb:1433"}, Score: 60},
		{SamAccountName: "Administrator", Type: "HVT", Score: 90},
	})
	adv := map[string]interface{}{
		"shares": []string{"Logs"},
		"sensitive_files": []advanced.FileFinding{
			{
				Share:     "Logs",
				Path:      "IdentitySync_Trace.log",
				Size:      128,
				Modified:  time.Now(),
				LootFound: []string{"Password: Welcome2026@"},
			},
		},
		"sessions": []advanced.SessionResult{
			{SamAccountName: "Administrator", LikelyActive: true, LogonCount: 5},
		},
	}

	graph := BuildGraph(BuildContext{
		Target:      "10.129.29.229",
		Domain:      "LOGGING.HTB",
		CurrentUser: "wallace.everette@logging.htb",
		Mode:        "aggressive",
		Services:    []string{"LDAP:389", "SMB:445"},
	}, users, candidates, adv)

	if graph.Summary.TotalNodes == 0 || graph.Summary.TotalEdges == 0 {
		t.Fatalf("expected graph nodes and edges, got %+v", graph.Summary)
	}
	if graph.Summary.AttackPaths == 0 {
		t.Fatal("expected at least one attack path")
	}
	if graph.Summary.StatusCounts[krb.StatusValidated] == 0 {
		t.Fatal("expected validated graph relationships")
	}
	if graph.Summary.NodeCounts["share"] == 0 {
		t.Fatal("expected share node from SMB results")
	}
}

func TestBuildGraphConnectsAdvancedModuleOutputs(t *testing.T) {
	rbcd := &advanced.RBCDResult{
		TargetDN:            "CN=WEB01,OU=Servers,DC=logging,DC=htb",
		TargetName:          "WEB01$",
		AllowedToActOn:      []string{"CN=svc_web,OU=Service Accounts,DC=logging,DC=htb"},
		RiskLevel:           "High",
		ExploitabilityScore: 90,
		ExploitationPath:    []string{"Compromise account with RBCD rights"},
	}
	s4u := &advanced.S4UResult{
		AccountDN:             "CN=svc_web,OU=Service Accounts,DC=logging,DC=htb",
		AccountName:           "svc_web",
		DelegationType:        "Constrained",
		TrustedForDelegation:  true,
		ServicePrincipalNames: []string{"HTTP/web01.logging.htb"},
		RiskLevel:             "High",
		ExploitabilityScore:   85,
		ExploitationPath:      []string{"Use S4U2Proxy to impersonate users"},
	}
	dcsync := &advanced.DCSyncResult{
		AccountDN:           "DC=logging,DC=htb",
		AccountName:         "(domain)",
		ReplicationRights:   []string{"DS-Replication-Get-Changes-All"},
		RiskLevel:           "High",
		ExploitabilityScore: 95,
	}
	adv := map[string]interface{}{
		"trusts": []advanced.TrustResult{
			{TrustName: "CORP", Direction: "Bidirectional", TrustType: "Forest", Partner: "corp.local"},
		},
		"dns_transfers": []advanced.DNSZoneTransferResult{
			{Nameserver: "dc01.logging.htb", Zone: "logging.htb", RecordCount: 4},
		},
		"laps": []advanced.LAPSResult{
			{Computer: "WS01", Password: "redacted", Source: "CN=WS01,DC=logging,DC=htb"},
			{Account: "svc_gmsa$", GMSA: true, Source: "CN=svc_gmsa,CN=Managed Service Accounts,DC=logging,DC=htb"},
		},
		"gpos": []advanced.GPOResult{
			{CN: "{11111111-1111-1111-1111-111111111111}", DisplayName: "Default Domain Policy"},
		},
		"rbcd": map[string]interface{}{
			"high_risk_targets": []*advanced.RBCDResult{rbcd},
		},
		"s4u": map[string]interface{}{
			"high_risk_accounts":       []*advanced.S4UResult{s4u},
			"unconstrained_delegation": []*advanced.S4UResult{s4u},
		},
		"pkinit": []*advanced.PKINITResult{
			{
				TemplateName:     "UserAuthentication",
				EnrollmentRights: []string{"CN=Domain Users,CN=Users,DC=logging,DC=htb"},
				Autoenrollment:   true,
				RiskLevel:        "High",
				RiskScore:        90,
				Exploitability:   []string{"Autoenrollment abuse via template"},
			},
		},
		"dcsync": map[string]interface{}{
			"high_risk_accounts": []*advanced.DCSyncResult{dcsync},
		},
	}

	graph := BuildGraph(BuildContext{Target: "dc01.logging.htb", Domain: "LOGGING.HTB"}, nil, nil, adv)

	expectedNodeTypes := []string{"trust", "dns_zone_transfer", "laps_secret", "gmsa_account", "gpo", "certificate_template", "replication_principal"}
	for _, nodeType := range expectedNodeTypes {
		if graph.Summary.NodeCounts[nodeType] == 0 {
			t.Fatalf("expected node type %q in graph summary, got %#v", nodeType, graph.Summary.NodeCounts)
		}
	}

	expectedEdges := []string{"has_trust", "tested_axfr", "contains_managed_credential", "has_gpo", "can_act_on_behalf", "delegates_to_spn", "can_enroll_certificate", "has_replication_rights"}
	for _, edgeType := range expectedEdges {
		if !hasEdgeType(graph, edgeType) {
			t.Fatalf("expected edge type %q in graph edges", edgeType)
		}
	}
}

func hasEdgeType(graph Graph, edgeType string) bool {
	for _, edge := range graph.Edges {
		if edge.Type == edgeType {
			return true
		}
	}
	return false
}
