package controlplane

import (
	"strings"

	"github.com/thechosenone-shall-prevail/cold-relay/pkg/advanced"
	"github.com/thechosenone-shall-prevail/cold-relay/pkg/reasoning"
)

func BuildFromReasoning(graph *reasoning.Graph, advResults map[string]interface{}) Graph {
	if graph == nil {
		return Graph{
			Coverage: []CoverageGap{
				{
					Area:      "attack_graph",
					Status:    StatusError,
					Gap:       "reasoning graph not available",
					Detail:    "No graph means rights-path synthesis cannot run.",
					NextCheck: "Ensure scan and reasoning phases complete successfully.",
				},
			},
		}
	}

	out := Graph{}
	nodeSeen := make(map[string]bool)
	for _, n := range graph.Nodes {
		out.Nodes = append(out.Nodes, Node{ID: n.ID, Type: n.Type, Name: n.Name})
		nodeSeen[n.ID] = true
	}

	for _, e := range graph.Edges {
		right, ok := mapEdgeToRight(e.Type)
		if !ok {
			continue
		}
		status := mapValidationToStatus(e.Validation)
		edge := Edge{
			Source:       e.From,
			Target:       e.To,
			Right:        right,
			Status:       status,
			Evidence:     append([]string{}, e.Evidence...),
			SourceModule: "reasoning",
		}
		if status == StatusUnknown {
			edge.HowToVerify = []string{
				"Validate this relationship with direct protocol evidence before action.",
			}
		}
		out.Edges = append(out.Edges, edge)
	}
	out.Edges = append(out.Edges, controlEdgesFromNTSecurityDescriptor(advResults)...)

	out.Coverage = append(out.Coverage, inferCoverageGaps(advResults)...)
	if _, ok := advResults["acl_control_edges"]; !ok {
		out.Coverage = append(out.Coverage, CoverageGap{
			Area:      "acl_effective_rights",
			Status:    StatusUnknown,
			Gap:       "GenericWrite/WriteDacl/WriteOwner style effective ACL rights are not fully modeled",
			Detail:    "Current run did not produce nTSecurityDescriptor-derived control edges.",
			NextCheck: "Run with LDAP permissions that allow reading security descriptors.",
		})
	}

	return out
}

func mapEdgeToRight(edgeType string) (string, bool) {
	switch strings.ToLower(edgeType) {
	case "member_of":
		return "MemberOf", true
	case "authenticated_to":
		return "AuthenticatedTo", true
	case "can_act_on_behalf":
		return "AllowedToAct", true
	case "delegates_to_spn", "allowed_to_delegate":
		return "DelegationPath", true
	case "has_replication_rights":
		return "ReplicationRights", true
	case "can_enroll_certificate":
		return "EnrollCertificate", true
	case "contains_sensitive_file":
		return "ReadSensitiveFile", true
	case "exposes_secret":
		return "ExtractSecret", true
	case "likely_active_session":
		return "SessionLead", true
	case "has_trust":
		return "TrustRelationship", true
	default:
		return "", false
	}
}

func mapValidationToStatus(validation string) Status {
	switch strings.ToLower(strings.TrimSpace(validation)) {
	case "validated":
		return StatusProvenTrue
	case "blocked":
		return StatusError
	case "insufficient_visibility":
		return StatusUnknown
	case "likely", "theoretical":
		return StatusUnknown
	default:
		return StatusUnknown
	}
}

func inferCoverageGaps(advResults map[string]interface{}) []CoverageGap {
	var gaps []CoverageGap
	required := []string{"trusts", "dns_transfers", "laps", "gpos", "sessions", "acl_analysis", "rbcd", "s4u", "pkinit", "dcsync"}
	for _, k := range required {
		if _, ok := advResults[k]; !ok {
			gaps = append(gaps, CoverageGap{
				Area:      k,
				Status:    StatusUnknown,
				Gap:       "module output missing",
				Detail:    "No results found for this analysis area in current run.",
				NextCheck: "Re-run in aggressive mode with sufficient privileges and network access.",
			})
		}
	}
	if v, ok := advResults["acl_analysis"]; ok {
		if acl, ok2 := v.([]advanced.ACLAnalysisResult); ok2 && len(acl) == 0 {
			gaps = append(gaps, CoverageGap{
				Area:      "acl_analysis",
				Status:    StatusUnknown,
				Gap:       "no ACL objects returned",
				Detail:    "Result set is empty; environment may be clean or visibility is constrained.",
				NextCheck: "Verify LDAP permissions to privileged object containers/security descriptors.",
			})
		}
	}
	return gaps
}

func controlEdgesFromNTSecurityDescriptor(advResults map[string]interface{}) []Edge {
	raw, ok := advResults["acl_control_edges"]
	if !ok {
		return nil
	}
	items, ok := raw.([]advanced.ACLControlEdge)
	if !ok {
		return nil
	}
	out := make([]Edge, 0, len(items))
	for _, item := range items {
		if item.TrusteeSID == "" || item.TargetDN == "" || item.Right == "" {
			continue
		}
		source := "sid:" + sanitizeID(item.TrusteeSID)
		if strings.TrimSpace(item.TrusteeDN) != "" {
			source = "object:" + sanitizeID(item.TrusteeDN)
		}
		out = append(out, Edge{
			Source:       source,
			Target:       "object:" + sanitizeID(item.TargetDN),
			Right:        item.Right,
			Status:       StatusProvenTrue,
			Evidence:     append([]string{}, item.Evidence...),
			HowToVerify:  []string{"Confirm principal resolution (SID->DN) and inherited ACE scope for this right."},
			SourceModule: "ntsecuritydescriptor",
		})
	}
	return out
}

func sanitizeID(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.NewReplacer("\\", "/", " ", "_", ",", "_", ":", "_", "|", "_", "$", "_").Replace(value)
	value = strings.Trim(value, "_")
	if value == "" {
		return "unknown"
	}
	return value
}

