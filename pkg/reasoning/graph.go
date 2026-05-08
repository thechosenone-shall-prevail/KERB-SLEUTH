package reasoning

import (
	"fmt"
	"sort"
	"strings"

	"github.com/thechosenone-shall-prevail/cold-relay/pkg/advanced"
	"github.com/thechosenone-shall-prevail/cold-relay/pkg/ingest"
	"github.com/thechosenone-shall-prevail/cold-relay/pkg/krb"
)

type BuildContext struct {
	Target      string   `json:"target,omitempty"`
	Domain      string   `json:"domain,omitempty"`
	CurrentUser string   `json:"current_user,omitempty"`
	Mode        string   `json:"mode,omitempty"`
	Services    []string `json:"services,omitempty"`
}

type Graph struct {
	Nodes       []Node       `json:"nodes"`
	Edges       []Edge       `json:"edges"`
	AttackPaths []AttackPath `json:"attack_paths,omitempty"`
	Summary     Summary      `json:"summary"`
}

type Summary struct {
	TotalNodes   int            `json:"total_nodes"`
	TotalEdges   int            `json:"total_edges"`
	AttackPaths  int            `json:"attack_paths"`
	NodeCounts   map[string]int `json:"node_counts,omitempty"`
	StatusCounts map[string]int `json:"status_counts,omitempty"`
}

type Node struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Name       string                 `json:"name"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type Edge struct {
	From       string                 `json:"from"`
	To         string                 `json:"to"`
	Type       string                 `json:"type"`
	Validation string                 `json:"validation"`
	Evidence   []string               `json:"evidence,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type AttackPath struct {
	Title      string     `json:"title"`
	Severity   string     `json:"severity"`
	Validation string     `json:"validation"`
	Steps      []PathStep `json:"steps"`
	Evidence   []string   `json:"evidence,omitempty"`
	Blockers   []string   `json:"blockers,omitempty"`
}

type PathStep struct {
	From       string   `json:"from"`
	To         string   `json:"to"`
	Action     string   `json:"action"`
	Validation string   `json:"validation"`
	Evidence   []string `json:"evidence,omitempty"`
}

type builder struct {
	nodes map[string]Node
	edges map[string]Edge
	paths []AttackPath
}

func AnnotateCandidates(candidates []krb.Candidate) []krb.Candidate {
	out := make([]krb.Candidate, len(candidates))
	copy(out, candidates)
	for i := range out {
		if out[i].Validation != "" {
			continue
		}
		switch out[i].Type {
		case "ASREP":
			if out[i].Hash != "" {
				krb.SetCandidateValidation(&out[i], krb.StatusValidated,
					[]string{"KDC returned an AS-REP and a crackable hash was captured."}, nil,
					[]string{"Export hash material and attempt offline cracking."})
			} else {
				krb.SetCandidateValidation(&out[i], krb.StatusTheoretical,
					[]string{"LDAP shows DONT_REQ_PREAUTH on an enabled user account."},
					[]string{"No live AS-REP hash has been captured for this candidate in current results."},
					[]string{"Validate against the KDC before treating this as exploitable."})
			}
		case "KERBEROAST":
			if out[i].Hash != "" {
				krb.SetCandidateValidation(&out[i], krb.StatusValidated,
					[]string{"KDC returned a service ticket and a crackable TGS hash was captured."}, nil,
					[]string{"Export hash material and attempt offline cracking."})
			} else {
				krb.SetCandidateValidation(&out[i], krb.StatusTheoretical,
					[]string{"LDAP shows one or more SPNs on an enabled user account."},
					[]string{"No live TGS hash has been captured for this candidate in current results."},
					[]string{"Validate ticket request success and encryption type before prioritizing."})
			}
		case "HVT":
			krb.SetCandidateValidation(&out[i], krb.StatusLikely,
				[]string{"LDAP group membership marks this principal as privileged."},
				[]string{"No current credential, session, or control edge proves access to this principal."},
				[]string{
					"Look for reachable credentials, sessions, ACL writes, or delegation edges into this principal.",
					"Double-verify: privileged group membership does not prove current compromise path.",
				})
		case "LOOT":
			krb.SetCandidateValidation(&out[i], krb.StatusLikely,
				[]string{"Secret-like material was observed in collected data."},
				[]string{"Pattern-based extraction can include false positives without full context."},
				[]string{
					"Manually verify the secret and test reuse with OPSEC controls.",
					"Double-verify: confirm source file/attribute context before treating as valid credential.",
				})
		case "RECON":
			krb.SetCandidateValidation(&out[i], krb.StatusLikely,
				[]string{"The referenced resource was reachable during collection."},
				[]string{"Reachability alone does not prove credential abuse or privilege escalation."},
				[]string{
					"Review collected files and connect the resource to principals or credentials.",
					"Double-verify: validate exploitation path with a protocol-specific control step.",
				})
		default:
			krb.SetCandidateValidation(&out[i], krb.StatusLikely,
				[]string{"Heuristic finding generated from collected directory or network context."}, nil,
				[]string{"Validate with a protocol-specific check before action."})
		}
		addHeuristicGuardrail(&out[i])
	}
	return out
}

func addHeuristicGuardrail(candidate *krb.Candidate) {
	if candidate == nil {
		return
	}
	if candidate.Validation == krb.StatusLikely || candidate.Validation == krb.StatusTheoretical {
		candidate.Blockers = appendUnique(candidate.Blockers,
			"Heuristic assessment may be incomplete under partial visibility; verify independently before action.")
		candidate.NextActions = appendUnique(candidate.NextActions,
			"Double-verify with direct protocol evidence (auth success, ticket capture, share mount, or ACL proof).")
	}
}

func BuildGraph(ctx BuildContext, users []ingest.User, candidates []krb.Candidate, advResults map[string]interface{}) Graph {
	b := &builder{
		nodes: make(map[string]Node),
		edges: make(map[string]Edge),
	}
	b.addNode("session:active", "session_state", "likely active session", nil)
	b.addNode("privilege:protected", "privilege", "protected privileged object", nil)
	b.addNode("privilege:domain", "privilege", "domain privilege objective", nil)
	b.addNode("share:*", "share_set", "readable shares", nil)
	b.addNode("file:*", "file_set", "sensitive files", nil)
	b.addNode("secret:*", "secret_set", "secret-like material", nil)
	b.addNode("share:admin", "share", "administrative shares", nil)
	b.addNode("principal:*", "principal_set", "eligible principals", nil)
	b.addNode("delegation:source", "delegation_set", "delegation source", nil)
	b.addNode("delegation:target", "delegation_set", "delegation target", nil)

	targetID := targetID(ctx.Target)
	if ctx.Target != "" {
		b.addNode(targetID, "target", ctx.Target, map[string]interface{}{
			"domain": ctx.Domain,
			"mode":   ctx.Mode,
		})
	}
	domainID := domainID(ctx.Domain)
	if ctx.Domain != "" {
		b.addNode(domainID, "domain", ctx.Domain, nil)
		if ctx.Target != "" {
			b.addEdge(targetID, domainID, "hosts_domain_services", krb.StatusLikely,
				[]string{"Target accepted AD protocol connections and LDAP returned a domain context."}, nil)
		}
	}
	if ctx.CurrentUser != "" {
		currentUserID := principalID(ctx.CurrentUser)
		b.addNode(currentUserID, "principal", ctx.CurrentUser, map[string]interface{}{"source": "bind_credentials"})
		if ctx.Target != "" {
			b.addEdge(currentUserID, targetID, "authenticated_to", krb.StatusValidated,
				[]string{"LDAP bind completed successfully with supplied credentials."}, nil)
		}
	}

	for _, service := range ctx.Services {
		serviceID, serviceName := serviceNode(ctx.Target, service)
		if serviceID == "" {
			continue
		}
		b.addNode(serviceID, "service", serviceName, map[string]interface{}{"raw": service})
		if ctx.Target != "" {
			b.addEdge(targetID, serviceID, "exposes_service", krb.StatusValidated,
				[]string{"TCP connect succeeded during protocol discovery."}, nil)
		}
	}

	userByName := make(map[string]ingest.User)
	for _, user := range users {
		if user.SamAccountName == "" {
			continue
		}
		uid := principalID(user.SamAccountName)
		userByName[strings.ToLower(user.SamAccountName)] = user
		b.addNode(uid, "principal", user.SamAccountName, map[string]interface{}{
			"distinguished_name": user.DistinguishedName,
			"disabled":           user.UserAccountControl&0x2 != 0,
			"spn_count":          len(user.ServicePrincipalNames),
			"preauth_not_needed": user.DoesNotRequirePreAuth || (user.UserAccountControl&0x400000) != 0,
		})
		for _, group := range user.MemberOf {
			gid := groupID(group)
			b.addNode(gid, "group", displayName(group), map[string]interface{}{"dn": group})
			b.addEdge(uid, gid, "member_of", krb.StatusValidated,
				[]string{"LDAP memberOf attribute returned this group."}, nil)
		}
		for _, spn := range user.ServicePrincipalNames {
			sid := spnID(spn)
			b.addNode(sid, "spn", spn, nil)
			b.addEdge(uid, sid, "owns_spn", krb.StatusValidated,
				[]string{"LDAP servicePrincipalName attribute returned this SPN."}, nil)
		}
	}

	for _, candidate := range candidates {
		findingID := findingID(candidate)
		b.addNode(findingID, "finding", candidate.Type+" "+candidate.SamAccountName, map[string]interface{}{
			"type":       candidate.Type,
			"score":      candidate.Score,
			"validation": candidate.Validation,
			"reasons":    candidate.Reasons,
		})
		fromID := principalID(candidate.SamAccountName)
		if candidate.Type == "RECON" {
			fromID = shareID(candidate.SamAccountName)
			b.addNode(fromID, "share", candidate.SamAccountName, map[string]interface{}{"source": "recon_candidate"})
		}
		b.addEdge(fromID, findingID, "has_finding", safeStatus(candidate.Validation), candidate.Evidence, map[string]interface{}{
			"blockers":     candidate.Blockers,
			"next_actions": candidate.NextActions,
		})
		b.addCandidatePath(candidate)
	}

	b.addShares(ctx, advResults)
	b.addSessions(userByName, advResults)
	b.addACLObjects(advResults)
	b.addInfrastructure(ctx, advResults)
	b.addDelegationFindings(advResults)
	b.addCertificateFindings(advResults)
	b.addDCSyncFindings(ctx, advResults)
	b.addAdvancedPaths(ctx, advResults)

	return b.graph()
}

func (b *builder) addShares(ctx BuildContext, advResults map[string]interface{}) {
	shares := asStringSlice(advResults["shares"])
	for _, share := range shares {
		sid := shareID(share)
		b.addNode(sid, "share", share, nil)
		if ctx.Target != "" {
			b.addEdge(targetID(ctx.Target), sid, "exposes_share", krb.StatusValidated,
				[]string{"SMB share enumeration returned this share."}, nil)
		}
	}

	findings := asFileFindings(advResults["sensitive_files"])
	for _, finding := range findings {
		sid := shareID(finding.Share)
		b.addNode(sid, "share", finding.Share, nil)
		fid := fileID(finding.Share, finding.Path)
		b.addNode(fid, "file", finding.Path, map[string]interface{}{
			"share":    finding.Share,
			"size":     finding.Size,
			"modified": finding.Modified,
		})
		b.addEdge(sid, fid, "contains_sensitive_file", krb.StatusValidated,
			[]string{"File was readable over SMB and matched sensitive filename/content heuristics."}, nil)
		for _, loot := range finding.LootFound {
			lid := secretID(finding.Share, finding.Path, loot)
			b.addNode(lid, "secret", "secret-like material", map[string]interface{}{
				"source": finding.Path,
				"value":  loot,
			})
			b.addEdge(fid, lid, "exposes_secret", krb.StatusValidated,
				[]string{"Secret-like string was observed while reading the file."}, nil)
		}
	}

	if len(findings) > 0 {
		status := krb.StatusLikely
		evidence := []string{"Readable SMB files were collected from sensitive shares."}
		for _, finding := range findings {
			if len(finding.LootFound) > 0 {
				status = krb.StatusValidated
				evidence = append(evidence, "At least one collected file contained secret-like material.")
				break
			}
		}
		b.paths = append(b.paths, AttackPath{
			Title:      "Readable share to credential discovery",
			Severity:   severityForStatus(status, "high"),
			Validation: status,
			Evidence:   evidence,
			Blockers:   blockersForSharePath(status),
			Steps: []PathStep{
				{From: targetID(ctx.Target), To: "share:*", Action: "Enumerate readable SMB shares", Validation: krb.StatusValidated, Evidence: []string{"SMB share enumeration succeeded."}},
				{From: "share:*", To: "file:*", Action: "Read sensitive files from juicy shares", Validation: krb.StatusValidated, Evidence: []string{"Sensitive files were opened and downloaded."}},
				{From: "file:*", To: "secret:*", Action: "Extract credential-like material", Validation: status, Evidence: evidence},
			},
		})
	}
}

func (b *builder) addSessions(userByName map[string]ingest.User, advResults map[string]interface{}) {
	for _, session := range asSessionResults(advResults["sessions"]) {
		if !session.LikelyActive || session.SamAccountName == "" {
			continue
		}
		uid := principalID(session.SamAccountName)
		b.addNode(uid, "principal", session.SamAccountName, nil)
		b.addEdge(uid, "session:active", "likely_active_session", krb.StatusLikely,
			[]string{"LDAP logon timestamps indicate recent account activity."}, map[string]interface{}{
				"last_logon":           session.LastLogon,
				"last_logon_timestamp": session.LastLogonTimestamp,
				"logon_count":          session.LogonCount,
			})
		if user, ok := userByName[strings.ToLower(session.SamAccountName)]; ok && hasPrivilegedGroup(user.MemberOf) {
			b.paths = append(b.paths, AttackPath{
				Title:      fmt.Sprintf("Privileged active-session lead: %s", session.SamAccountName),
				Severity:   "high",
				Validation: krb.StatusLikely,
				Evidence:   []string{"User is privileged and LDAP timestamps suggest recent activity."},
				Blockers:   []string{"LDAP logon timestamps do not prove host locality or current interactive session."},
				Steps: []PathStep{
					{From: uid, To: "session:active", Action: "Prioritize session locality validation", Validation: krb.StatusLikely, Evidence: []string{"Recent logon metadata observed."}},
				},
			})
		}
	}
}

func (b *builder) addACLObjects(advResults map[string]interface{}) {
	for _, acl := range asACLResults(advResults["acl_analysis"]) {
		if acl.ObjectDN == "" {
			continue
		}
		oid := objectID(acl.ObjectDN)
		b.addNode(oid, "directory_object", displayName(acl.ObjectDN), map[string]interface{}{
			"dn":                         acl.ObjectDN,
			"object_type":                acl.ObjectType,
			"admin_count":                acl.AdminCount,
			"high_privilege_memberships": acl.HighPrivilegeMemberships,
			"notes":                      acl.Notes,
		})
		if acl.AdminCount || len(acl.HighPrivilegeMemberships) > 0 {
			b.addEdge(oid, "privilege:protected", "marked_privileged", krb.StatusValidated,
				[]string{"LDAP adminCount or high-privilege membership was observed."}, nil)
		}
	}
}

func (b *builder) addInfrastructure(ctx BuildContext, advResults map[string]interface{}) {
	did := domainID(ctx.Domain)
	for _, trust := range asTrustResults(advResults["trusts"]) {
		tid := trustID(trust.TrustName, trust.Partner)
		b.addNode(tid, "trust", trust.TrustName, map[string]interface{}{
			"type":       trust.TrustType,
			"direction":  trust.Direction,
			"transitive": trust.IsTransitive,
			"partner":    trust.Partner,
			"sid":        trust.SID,
		})
		b.addEdge(did, tid, "has_trust", krb.StatusValidated,
			[]string{"LDAP trust enumeration returned this trusted domain object."}, nil)
		if strings.EqualFold(trust.Direction, "Bidirectional") || strings.EqualFold(trust.Direction, "Outbound") {
			b.paths = append(b.paths, AttackPath{
				Title:      "Trust relationship pivot lead: " + trust.TrustName,
				Severity:   "medium",
				Validation: krb.StatusTheoretical,
				Evidence:   []string{"Domain trust relationship exists."},
				Blockers:   []string{"Trust direction does not prove credentials, SID filtering state, or reachable attack primitive."},
				Steps: []PathStep{
					{From: did, To: tid, Action: "Validate trust direction, SID filtering, and reachable principals", Validation: krb.StatusTheoretical, Evidence: []string{"Trust object was enumerated."}},
				},
			})
		}
	}

	for _, dnsResult := range asDNSResults(advResults["dns_transfers"]) {
		zid := dnsZoneID(dnsResult.Zone, dnsResult.Nameserver)
		status := krb.StatusBlocked
		evidence := []string{"AXFR attempt completed with an error or no records."}
		if dnsResult.RecordCount > 0 {
			status = krb.StatusValidated
			evidence = []string{fmt.Sprintf("AXFR returned %d DNS records.", dnsResult.RecordCount)}
		}
		b.addNode(zid, "dns_zone_transfer", dnsResult.Zone, map[string]interface{}{
			"nameserver":   dnsResult.Nameserver,
			"record_count": dnsResult.RecordCount,
			"error":        dnsResult.Error,
		})
		b.addEdge(did, zid, "tested_axfr", status, evidence, nil)
	}

	for _, laps := range asLAPSResults(advResults["laps"]) {
		name := laps.Computer
		if name == "" {
			name = laps.Account
		}
		lid := lapsID(name)
		nodeType := "laps_secret"
		if laps.GMSA {
			nodeType = "gmsa_account"
		}
		status := krb.StatusValidated
		evidence := []string{"LDAP returned LAPS/gMSA-related attributes."}
		if laps.Password == "" && !laps.GMSA {
			status = krb.StatusLikely
			evidence = []string{"LDAP returned LAPS metadata but no readable password value."}
		}
		b.addNode(lid, nodeType, name, map[string]interface{}{
			"computer": laps.Computer,
			"account":  laps.Account,
			"source":   laps.Source,
			"expires":  laps.Expires,
			"gmsa":     laps.GMSA,
		})
		b.addEdge(did, lid, "contains_managed_credential", status, evidence, nil)
	}

	for _, gpo := range asGPOResults(advResults["gpos"]) {
		gid := gpoID(gpo.CN, gpo.DisplayName)
		b.addNode(gid, "gpo", firstNonEmpty(gpo.DisplayName, gpo.CN), map[string]interface{}{
			"cn":              gpo.CN,
			"filesystem_path": gpo.FileSysPath,
			"gpo_options":     gpo.GPOptions,
			"notes":           gpo.Notes,
		})
		status := krb.StatusValidated
		if len(gpo.Notes) > 0 {
			status = krb.StatusLikely
		}
		b.addEdge(did, gid, "has_gpo", status,
			[]string{"LDAP Group Policy container enumeration returned this GPO."}, nil)
	}
}

func (b *builder) addDelegationFindings(advResults map[string]interface{}) {
	for _, rbcd := range asRBCDResultsFromReport(advResults["rbcd"]) {
		tid := objectID(rbcd.TargetDN)
		b.addNode(tid, "delegation_target", firstNonEmpty(rbcd.TargetName, rbcd.TargetDN), map[string]interface{}{
			"target_dn":      rbcd.TargetDN,
			"allowed_to_act": rbcd.AllowedToActOn,
			"risk_level":     rbcd.RiskLevel,
			"score":          rbcd.ExploitabilityScore,
		})
		for _, allowed := range rbcd.AllowedToActOn {
			aid := objectID(allowed)
			b.addNode(aid, "delegation_principal", displayName(allowed), map[string]interface{}{"raw": allowed})
			b.addEdge(aid, tid, "can_act_on_behalf", validationFromRisk(rbcd.RiskLevel),
				[]string{"RBCD attribute msDS-AllowedToActOnBehalfOfOtherIdentity was present."}, nil)
		}
		b.addDelegationPath("RBCD delegation path: "+firstNonEmpty(rbcd.TargetName, rbcd.TargetDN), rbcd.RiskLevel, rbcd.ExploitationPath)
	}

	for _, s4u := range asS4UResultsFromReport(advResults["s4u"]) {
		aid := principalID(firstNonEmpty(s4u.AccountName, s4u.AccountDN))
		b.addNode(aid, "delegation_account", firstNonEmpty(s4u.AccountName, s4u.AccountDN), map[string]interface{}{
			"account_dn":      s4u.AccountDN,
			"delegation_type": s4u.DelegationType,
			"trusted":         s4u.TrustedForDelegation,
			"risk_level":      s4u.RiskLevel,
			"score":           s4u.ExploitabilityScore,
		})
		for _, spn := range s4u.ServicePrincipalNames {
			sid := spnID(spn)
			b.addNode(sid, "spn", spn, nil)
			b.addEdge(aid, sid, "delegates_to_spn", validationFromRisk(s4u.RiskLevel),
				[]string{"S4U/delegation LDAP attributes reference this service."}, nil)
		}
		for _, target := range s4u.AllowedToActOn {
			tid := objectID(target)
			b.addNode(tid, "delegation_target", displayName(target), map[string]interface{}{"raw": target})
			b.addEdge(aid, tid, "allowed_to_delegate", validationFromRisk(s4u.RiskLevel),
				[]string{"S4U/delegation LDAP attributes reference this target."}, nil)
		}
		b.addDelegationPath("S4U delegation path: "+firstNonEmpty(s4u.AccountName, s4u.AccountDN), s4u.RiskLevel, s4u.ExploitationPath)
	}
}

func (b *builder) addCertificateFindings(advResults map[string]interface{}) {
	for _, template := range asPKINITResults(advResults["pkinit"]) {
		tid := certTemplateID(template.TemplateName)
		b.addNode(tid, "certificate_template", template.TemplateName, map[string]interface{}{
			"dn":                template.TemplateDN,
			"autoenrollment":    template.Autoenrollment,
			"smartcard_logon":   template.SmartCardLogon,
			"risk_level":        template.RiskLevel,
			"risk_score":        template.RiskScore,
			"enrollment_rights": template.EnrollmentRights,
		})
		for _, right := range template.EnrollmentRights {
			rid := objectID(right)
			b.addNode(rid, "enrollment_principal", displayName(right), map[string]interface{}{"raw": right})
			b.addEdge(rid, tid, "can_enroll_certificate", validationFromRisk(template.RiskLevel),
				[]string{"Certificate template enrollment rights include this principal."}, nil)
		}
		if len(template.Exploitability) > 0 {
			b.paths = append(b.paths, AttackPath{
				Title:      "AD CS template abuse lead: " + template.TemplateName,
				Severity:   strings.ToLower(firstNonEmpty(template.RiskLevel, "medium")),
				Validation: validationFromRisk(template.RiskLevel),
				Evidence:   template.Exploitability,
				Blockers:   []string{"Template attributes alone do not prove enrollment success, CA reachability, or ESC exploitability."},
				Steps: []PathStep{
					{From: "principal:*", To: tid, Action: "Validate enrollment and certificate authentication path", Validation: validationFromRisk(template.RiskLevel), Evidence: template.Exploitability},
				},
			})
		}
	}
}

func (b *builder) addDCSyncFindings(ctx BuildContext, advResults map[string]interface{}) {
	for _, dcsync := range asDCSyncResultsFromReport(advResults["dcsync"]) {
		aid := objectID(firstNonEmpty(dcsync.AccountDN, dcsync.AccountName))
		b.addNode(aid, "replication_principal", firstNonEmpty(dcsync.AccountName, dcsync.AccountDN), map[string]interface{}{
			"account_dn": dcsync.AccountDN,
			"rights":     dcsync.ReplicationRights,
			"risk_level": dcsync.RiskLevel,
			"score":      dcsync.ExploitabilityScore,
		})
		b.addEdge(aid, domainID(ctx.Domain), "has_replication_rights", validationFromRisk(dcsync.RiskLevel),
			[]string{"DCSync-class replication rights were identified in collected directory data."}, nil)
		b.paths = append(b.paths, AttackPath{
			Title:      "DCSync replication-rights lead: " + firstNonEmpty(dcsync.AccountName, dcsync.AccountDN),
			Severity:   strings.ToLower(firstNonEmpty(dcsync.RiskLevel, "high")),
			Validation: validationFromRisk(dcsync.RiskLevel),
			Evidence:   dcsync.ReplicationRights,
			Blockers:   []string{"Current DCSync module may identify right presence without resolving every effective principal from the security descriptor."},
			Steps: []PathStep{
				{From: aid, To: domainID(ctx.Domain), Action: "Validate effective replication rights and DCSync viability", Validation: validationFromRisk(dcsync.RiskLevel), Evidence: dcsync.ReplicationRights},
			},
		})
	}
}

func (b *builder) addDelegationPath(title, risk string, rawSteps []string) {
	if len(rawSteps) == 0 {
		return
	}
	steps := make([]PathStep, 0, len(rawSteps))
	for _, raw := range rawSteps {
		steps = append(steps, PathStep{
			From:       "delegation:source",
			To:         "delegation:target",
			Action:     raw,
			Validation: validationFromRisk(risk),
			Evidence:   []string{"Delegation analysis generated this deterministic step."},
		})
	}
	b.paths = append(b.paths, AttackPath{
		Title:      title,
		Severity:   strings.ToLower(firstNonEmpty(risk, "medium")),
		Validation: validationFromRisk(risk),
		Evidence:   []string{"Delegation attributes were present in LDAP results."},
		Blockers:   []string{"Delegation configuration does not prove credential control over the source principal."},
		Steps:      steps,
	})
}

func (b *builder) addAdvancedPaths(ctx BuildContext, advResults map[string]interface{}) {
	if pwned, ok := advResults["pwned"].(bool); ok && pwned {
		b.paths = append(b.paths, AttackPath{
			Title:      "Authenticated SMB administrative access",
			Severity:   "critical",
			Validation: krb.StatusValidated,
			Evidence:   []string{"ADMIN$ or C$ mounted successfully over SMB."},
			Steps: []PathStep{
				{From: principalID(ctx.CurrentUser), To: targetID(ctx.Target), Action: "Authenticate to SMB", Validation: krb.StatusValidated, Evidence: []string{"SMB session established."}},
				{From: targetID(ctx.Target), To: "share:admin", Action: "Mount administrative share", Validation: krb.StatusValidated, Evidence: []string{"ADMIN$ or C$ access succeeded."}},
			},
		})
	}
}

func (b *builder) addCandidatePath(candidate krb.Candidate) {
	switch candidate.Type {
	case "ASREP":
		b.paths = append(b.paths, AttackPath{
			Title:      "AS-REP roast candidate: " + candidate.SamAccountName,
			Severity:   candidateSeverity(candidate),
			Validation: safeStatus(candidate.Validation),
			Evidence:   candidate.Evidence,
			Blockers:   candidate.Blockers,
			Steps: []PathStep{
				{From: principalID(candidate.SamAccountName), To: findingID(candidate), Action: "Validate no-preauth KDC response", Validation: safeStatus(candidate.Validation), Evidence: candidate.Evidence},
			},
		})
	case "KERBEROAST":
		b.paths = append(b.paths, AttackPath{
			Title:      "Kerberoast candidate: " + candidate.SamAccountName,
			Severity:   candidateSeverity(candidate),
			Validation: safeStatus(candidate.Validation),
			Evidence:   candidate.Evidence,
			Blockers:   candidate.Blockers,
			Steps: []PathStep{
				{From: principalID(candidate.SamAccountName), To: findingID(candidate), Action: "Validate TGS request and hash capture", Validation: safeStatus(candidate.Validation), Evidence: candidate.Evidence},
			},
		})
	case "HVT":
		b.paths = append(b.paths, AttackPath{
			Title:      "Privileged account target: " + candidate.SamAccountName,
			Severity:   "critical",
			Validation: krb.StatusTheoretical,
			Evidence:   candidate.Evidence,
			Blockers:   candidate.Blockers,
			Steps: []PathStep{
				{From: principalID(candidate.SamAccountName), To: "privilege:domain", Action: "Treat as high-value objective, not an access path", Validation: krb.StatusTheoretical, Evidence: candidate.Evidence},
			},
		})
	case "LOOT":
		b.paths = append(b.paths, AttackPath{
			Title:      "Plaintext secret lead: " + candidate.SamAccountName,
			Severity:   "critical",
			Validation: safeStatus(candidate.Validation),
			Evidence:   candidate.Evidence,
			Steps: []PathStep{
				{From: findingID(candidate), To: principalID(candidate.SamAccountName), Action: "Manually verify secret and map reuse scope", Validation: safeStatus(candidate.Validation), Evidence: candidate.Evidence},
			},
		})
	}
}

func (b *builder) addNode(id, typ, name string, props map[string]interface{}) {
	if id == "" {
		return
	}
	if existing, ok := b.nodes[id]; ok {
		if existing.Properties == nil {
			existing.Properties = props
		} else {
			for k, v := range props {
				existing.Properties[k] = v
			}
		}
		b.nodes[id] = existing
		return
	}
	if props == nil {
		props = make(map[string]interface{})
	}
	b.nodes[id] = Node{ID: id, Type: typ, Name: name, Properties: props}
}

func (b *builder) addEdge(from, to, typ, validation string, evidence []string, props map[string]interface{}) {
	if from == "" || to == "" {
		return
	}
	key := from + "|" + typ + "|" + to
	if existing, ok := b.edges[key]; ok {
		existing.Evidence = appendUnique(existing.Evidence, evidence...)
		if existing.Properties == nil {
			existing.Properties = props
		} else {
			for k, v := range props {
				existing.Properties[k] = v
			}
		}
		b.edges[key] = existing
		return
	}
	if props == nil {
		props = make(map[string]interface{})
	}
	b.edges[key] = Edge{
		From:       from,
		To:         to,
		Type:       typ,
		Validation: safeStatus(validation),
		Evidence:   appendUnique(nil, evidence...),
		Properties: props,
	}
}

func (b *builder) graph() Graph {
	nodes := make([]Node, 0, len(b.nodes))
	for _, node := range b.nodes {
		nodes = append(nodes, node)
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })

	edges := make([]Edge, 0, len(b.edges))
	for _, edge := range b.edges {
		edges = append(edges, edge)
	}
	sort.Slice(edges, func(i, j int) bool {
		return edges[i].From+"|"+edges[i].Type+"|"+edges[i].To < edges[j].From+"|"+edges[j].Type+"|"+edges[j].To
	})

	nodeCounts := make(map[string]int)
	statusCounts := make(map[string]int)
	for _, node := range nodes {
		nodeCounts[node.Type]++
	}
	for _, edge := range edges {
		statusCounts[edge.Validation]++
	}
	for _, path := range b.paths {
		statusCounts[path.Validation]++
	}

	return Graph{
		Nodes:       nodes,
		Edges:       edges,
		AttackPaths: b.paths,
		Summary: Summary{
			TotalNodes:   len(nodes),
			TotalEdges:   len(edges),
			AttackPaths:  len(b.paths),
			NodeCounts:   nodeCounts,
			StatusCounts: statusCounts,
		},
	}
}

func asStringSlice(value interface{}) []string {
	items, ok := value.([]string)
	if !ok {
		return nil
	}
	return items
}

func asFileFindings(value interface{}) []advanced.FileFinding {
	items, ok := value.([]advanced.FileFinding)
	if !ok {
		return nil
	}
	return items
}

func asSessionResults(value interface{}) []advanced.SessionResult {
	items, ok := value.([]advanced.SessionResult)
	if !ok {
		return nil
	}
	return items
}

func asACLResults(value interface{}) []advanced.ACLAnalysisResult {
	items, ok := value.([]advanced.ACLAnalysisResult)
	if !ok {
		return nil
	}
	return items
}

func asTrustResults(value interface{}) []advanced.TrustResult {
	items, ok := value.([]advanced.TrustResult)
	if !ok {
		return nil
	}
	return items
}

func asDNSResults(value interface{}) []advanced.DNSZoneTransferResult {
	items, ok := value.([]advanced.DNSZoneTransferResult)
	if !ok {
		return nil
	}
	return items
}

func asLAPSResults(value interface{}) []advanced.LAPSResult {
	items, ok := value.([]advanced.LAPSResult)
	if !ok {
		return nil
	}
	return items
}

func asGPOResults(value interface{}) []advanced.GPOResult {
	items, ok := value.([]advanced.GPOResult)
	if !ok {
		return nil
	}
	return items
}

func asPKINITResults(value interface{}) []*advanced.PKINITResult {
	items, ok := value.([]*advanced.PKINITResult)
	if !ok {
		return nil
	}
	return items
}

func asRBCDResultsFromReport(value interface{}) []*advanced.RBCDResult {
	report, ok := value.(map[string]interface{})
	if !ok {
		return nil
	}
	return appendResultSets(
		asRBCDResultSet(report["high_risk_targets"]),
	)
}

func asS4UResultsFromReport(value interface{}) []*advanced.S4UResult {
	report, ok := value.(map[string]interface{})
	if !ok {
		return nil
	}
	return appendS4USets(
		asS4UResultSet(report["high_risk_accounts"]),
		asS4UResultSet(report["unconstrained_delegation"]),
	)
}

func asDCSyncResultsFromReport(value interface{}) []*advanced.DCSyncResult {
	report, ok := value.(map[string]interface{})
	if !ok {
		return nil
	}
	items, ok := report["high_risk_accounts"].([]*advanced.DCSyncResult)
	if !ok {
		return nil
	}
	return items
}

func asRBCDResultSet(value interface{}) []*advanced.RBCDResult {
	items, ok := value.([]*advanced.RBCDResult)
	if !ok {
		return nil
	}
	return items
}

func asS4UResultSet(value interface{}) []*advanced.S4UResult {
	items, ok := value.([]*advanced.S4UResult)
	if !ok {
		return nil
	}
	return items
}

func appendResultSets(sets ...[]*advanced.RBCDResult) []*advanced.RBCDResult {
	seen := make(map[string]bool)
	var out []*advanced.RBCDResult
	for _, set := range sets {
		for _, item := range set {
			if item == nil {
				continue
			}
			key := item.TargetDN + "|" + item.TargetName
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, item)
		}
	}
	return out
}

func appendS4USets(sets ...[]*advanced.S4UResult) []*advanced.S4UResult {
	seen := make(map[string]bool)
	var out []*advanced.S4UResult
	for _, set := range sets {
		for _, item := range set {
			if item == nil {
				continue
			}
			key := item.AccountDN + "|" + item.AccountName
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, item)
		}
	}
	return out
}

func appendUnique(existing []string, values ...string) []string {
	seen := make(map[string]bool, len(existing)+len(values))
	out := make([]string, 0, len(existing)+len(values))
	for _, value := range existing {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func candidateSeverity(candidate krb.Candidate) string {
	for _, reason := range candidate.Reasons {
		lower := strings.ToLower(reason)
		if strings.Contains(lower, "severity: high") {
			return "high"
		}
		if strings.Contains(lower, "severity: medium") {
			return "medium"
		}
		if strings.Contains(lower, "severity: low") {
			return "low"
		}
	}
	if candidate.Score >= 90 {
		return "critical"
	}
	if candidate.Score >= 80 {
		return "high"
	}
	if candidate.Score >= 50 {
		return "medium"
	}
	return "low"
}

func severityForStatus(status, fallback string) string {
	if status == krb.StatusValidated {
		return "critical"
	}
	return fallback
}

func blockersForSharePath(status string) []string {
	if status == krb.StatusValidated {
		return nil
	}
	return []string{"Sensitive files were readable, but no secret-like material was confirmed in the sampled content."}
}

func safeStatus(status string) string {
	switch status {
	case krb.StatusValidated, krb.StatusLikely, krb.StatusTheoretical, krb.StatusBlocked, krb.StatusInsufficientVisibility:
		return status
	default:
		return krb.StatusLikely
	}
}

func validationFromRisk(risk string) string {
	switch strings.ToLower(strings.TrimSpace(risk)) {
	case "high":
		return krb.StatusLikely
	case "medium", "low":
		return krb.StatusTheoretical
	default:
		return krb.StatusTheoretical
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func hasPrivilegedGroup(groups []string) bool {
	for _, group := range groups {
		lower := strings.ToLower(group)
		if strings.Contains(lower, "domain admins") ||
			strings.Contains(lower, "enterprise admins") ||
			strings.Contains(lower, "schema admins") ||
			strings.Contains(lower, "administrators") {
			return true
		}
	}
	return false
}

func displayName(dn string) string {
	if dn == "" {
		return ""
	}
	for _, part := range strings.Split(dn, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(part), "CN=") && len(part) > 3 {
			return part[3:]
		}
	}
	return dn
}

func targetID(target string) string {
	if target == "" {
		return "target:unknown"
	}
	return "target:" + key(target)
}

func domainID(domain string) string {
	if domain == "" {
		return "domain:unknown"
	}
	return "domain:" + key(domain)
}

func principalID(name string) string {
	if name == "" {
		return "principal:unknown"
	}
	return "principal:" + key(name)
}

func groupID(name string) string {
	return "group:" + key(name)
}

func spnID(spn string) string {
	return "spn:" + key(spn)
}

func shareID(share string) string {
	if share == "" {
		return "share:unknown"
	}
	return "share:" + key(share)
}

func fileID(share, path string) string {
	return "file:" + key(share+"|"+path)
}

func secretID(share, path, value string) string {
	return "secret:" + key(share+"|"+path+"|"+value)
}

func objectID(dn string) string {
	return "object:" + key(dn)
}

func trustID(name, partner string) string {
	return "trust:" + key(name+"|"+partner)
}

func dnsZoneID(zone, nameserver string) string {
	return "dns_axfr:" + key(zone+"|"+nameserver)
}

func lapsID(name string) string {
	return "managed_credential:" + key(name)
}

func gpoID(cn, displayName string) string {
	return "gpo:" + key(cn+"|"+displayName)
}

func certTemplateID(name string) string {
	return "cert_template:" + key(name)
}

func findingID(candidate krb.Candidate) string {
	return "finding:" + key(candidate.Type+"|"+candidate.SamAccountName+"|"+strings.Join(candidate.SPNs, ","))
}

func serviceNode(target, service string) (string, string) {
	service = strings.TrimSpace(service)
	if service == "" {
		return "", ""
	}
	return "service:" + key(target+"|"+service), service
}

func key(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	replacer := strings.NewReplacer("\\", "/", " ", "_", ",", "_", ":", "_", "|", "_", "$", "_")
	value = replacer.Replace(value)
	value = strings.Trim(value, "_")
	if value == "" {
		return "unknown"
	}
	return value
}
