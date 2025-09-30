package bloodhound

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/thechosenone-shall-prevail/KERB-SLEUTH/pkg/krb"
)

// BloodHoundNode represents a node in BloodHound
type BloodHoundNode struct {
	ObjectIdentifier string                 `json:"ObjectIdentifier"`
	ObjectType       string                 `json:"ObjectType"`
	Properties       map[string]interface{} `json:"Properties"`
}

// BloodHoundEdge represents an edge/relationship in BloodHound
type BloodHoundEdge struct {
	Source     string                 `json:"Source"`
	Target     string                 `json:"Target"`
	EdgeType   string                 `json:"EdgeType"`
	Properties map[string]interface{} `json:"Properties"`
}

// BloodHoundData represents the complete BloodHound dataset
type BloodHoundData struct {
	Meta struct {
		Version    int    `json:"version"`
		Count      int    `json:"count"`
		Methods    int    `json:"methods"`
		Collection string `json:"collection"`
		Date       string `json:"date"`
	} `json:"meta"`
	Nodes []BloodHoundNode `json:"nodes"`
	Edges []BloodHoundEdge `json:"edges"`
}

// BloodHoundExporter handles BloodHound data export
type BloodHoundExporter struct {
	Domain string
	Nodes  map[string]*BloodHoundNode
	Edges  []BloodHoundEdge
}

// NewBloodHoundExporter creates a new BloodHound exporter
func NewBloodHoundExporter(domain string) *BloodHoundExporter {
	return &BloodHoundExporter{
		Domain: domain,
		Nodes:  make(map[string]*BloodHoundNode),
		Edges:  []BloodHoundEdge{},
	}
}

// AddUser adds a user to the BloodHound dataset
func (bhe *BloodHoundExporter) AddUser(username, distinguishedName string, isAdmin bool) {
	nodeID := fmt.Sprintf("%s@%s", username, bhe.Domain)

	node := &BloodHoundNode{
		ObjectIdentifier: nodeID,
		ObjectType:       "User",
		Properties: map[string]interface{}{
			"name":                    username,
			"distinguishedname":       distinguishedName,
			"domain":                  bhe.Domain,
			"enabled":                 true,
			"admincount":              isAdmin,
			"hasspn":                  false,
			"passwordnotreqd":         false,
			"unconstraineddelegation": false,
			"trustedfordelegation":    false,
		},
	}

	bhe.Nodes[nodeID] = node
	log.Printf("📊 Added user to BloodHound: %s", username)
}

// AddComputer adds a computer to the BloodHound dataset
func (bhe *BloodHoundExporter) AddComputer(computerName, distinguishedName string, isDC bool) {
	nodeID := fmt.Sprintf("%s@%s", computerName, bhe.Domain)

	nodeType := "Computer"
	if isDC {
		nodeType = "Domain"
	}

	node := &BloodHoundNode{
		ObjectIdentifier: nodeID,
		ObjectType:       nodeType,
		Properties: map[string]interface{}{
			"name":                    computerName,
			"distinguishedname":       distinguishedName,
			"domain":                  bhe.Domain,
			"enabled":                 true,
			"unconstraineddelegation": false,
			"trustedfordelegation":    false,
		},
	}

	bhe.Nodes[nodeID] = node
	log.Printf("📊 Added computer to BloodHound: %s", computerName)
}

// AddGroup adds a group to the BloodHound dataset
func (bhe *BloodHoundExporter) AddGroup(groupName, distinguishedName string, isHighValue bool) {
	nodeID := fmt.Sprintf("%s@%s", groupName, bhe.Domain)

	node := &BloodHoundNode{
		ObjectIdentifier: nodeID,
		ObjectType:       "Group",
		Properties: map[string]interface{}{
			"name":              groupName,
			"distinguishedname": distinguishedName,
			"domain":            bhe.Domain,
			"highvalue":         isHighValue,
		},
	}

	bhe.Nodes[nodeID] = node
	log.Printf("📊 Added group to BloodHound: %s", groupName)
}

// AddRBCDRelationship adds RBCD relationship
func (bhe *BloodHoundExporter) AddRBCDRelationship(sourceUser, targetComputer string) {
	sourceID := fmt.Sprintf("%s@%s", sourceUser, bhe.Domain)
	targetID := fmt.Sprintf("%s@%s", targetComputer, bhe.Domain)

	edge := BloodHoundEdge{
		Source:   sourceID,
		Target:   targetID,
		EdgeType: "AllowedToAct",
		Properties: map[string]interface{}{
			"isacl": false,
		},
	}

	bhe.Edges = append(bhe.Edges, edge)
	log.Printf("📊 Added RBCD relationship: %s -> %s", sourceUser, targetComputer)
}

// AddS4URelationship adds S4U delegation relationship
func (bhe *BloodHoundExporter) AddS4URelationship(sourceUser, targetService string) {
	sourceID := fmt.Sprintf("%s@%s", sourceUser, bhe.Domain)
	targetID := fmt.Sprintf("%s@%s", targetService, bhe.Domain)

	edge := BloodHoundEdge{
		Source:   sourceID,
		Target:   targetID,
		EdgeType: "TrustedForDelegation",
		Properties: map[string]interface{}{
			"isacl": false,
		},
	}

	bhe.Edges = append(bhe.Edges, edge)
	log.Printf("📊 Added S4U relationship: %s -> %s", sourceUser, targetService)
}

// AddGroupMembership adds group membership relationship
func (bhe *BloodHoundExporter) AddGroupMembership(user, group string) {
	userID := fmt.Sprintf("%s@%s", user, bhe.Domain)
	groupID := fmt.Sprintf("%s@%s", group, bhe.Domain)

	edge := BloodHoundEdge{
		Source:   userID,
		Target:   groupID,
		EdgeType: "MemberOf",
		Properties: map[string]interface{}{
			"isacl": false,
		},
	}

	bhe.Edges = append(bhe.Edges, edge)
	log.Printf("📊 Added group membership: %s -> %s", user, group)
}

// AddSPN adds Service Principal Name to a user
func (bhe *BloodHoundExporter) AddSPN(username, spn string) {
	nodeID := fmt.Sprintf("%s@%s", username, bhe.Domain)

	if node, exists := bhe.Nodes[nodeID]; exists {
		node.Properties["hasspn"] = true
		node.Properties["serviceprincipalnames"] = []string{spn}
		log.Printf("📊 Added SPN to user: %s -> %s", username, spn)
	}
}

// AddAttackPath adds an attack path to BloodHound
func (bhe *BloodHoundExporter) AddAttackPath(path []string, attackType string) {
	if len(path) < 2 {
		return
	}

	for i := 0; i < len(path)-1; i++ {
		sourceID := fmt.Sprintf("%s@%s", path[i], bhe.Domain)
		targetID := fmt.Sprintf("%s@%s", path[i+1], bhe.Domain)

		edge := BloodHoundEdge{
			Source:   sourceID,
			Target:   targetID,
			EdgeType: attackType,
			Properties: map[string]interface{}{
				"isacl":      false,
				"attackpath": true,
			},
		}

		bhe.Edges = append(bhe.Edges, edge)
	}

	log.Printf("📊 Added attack path: %s", attackType)
}

// ExportToBloodHound exports data to BloodHound format
func (bhe *BloodHoundExporter) ExportToBloodHound(outputFile string) error {
	log.Printf("📊 Exporting BloodHound data to: %s", outputFile)

	// Convert nodes map to slice
	nodes := make([]BloodHoundNode, 0, len(bhe.Nodes))
	for _, node := range bhe.Nodes {
		nodes = append(nodes, *node)
	}

	// Create BloodHound data structure
	data := BloodHoundData{
		Meta: struct {
			Version    int    `json:"version"`
			Count      int    `json:"count"`
			Methods    int    `json:"methods"`
			Collection string `json:"collection"`
			Date       string `json:"date"`
		}{
			Version:    4,
			Count:      len(nodes),
			Methods:    len(bhe.Edges),
			Collection: "kerb-sleuth",
			Date:       time.Now().Format(time.RFC3339),
		},
		Nodes: nodes,
		Edges: bhe.Edges,
	}

	// Marshal to JSON
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal BloodHound data: %v", err)
	}

	// Write to file
	err = os.WriteFile(outputFile, jsonData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write BloodHound file: %v", err)
	}

	log.Printf("✅ BloodHound data exported successfully: %d nodes, %d edges", len(nodes), len(bhe.Edges))
	return nil
}

// GenerateAttackPaths generates common attack paths from Kerberos analysis
func (bhe *BloodHoundExporter) GenerateAttackPaths(kerberosResults []krb.Candidate) {
	log.Printf("🔍 Generating attack paths from Kerberos analysis...")

	for _, candidate := range kerberosResults {
		switch candidate.Type {
		case "ASREP":
			// AS-REP roasting attack path
			path := []string{"Anonymous", candidate.SamAccountName, "Domain Admins"}
			bhe.AddAttackPath(path, "ASREPRoasting")

		case "KERBEROAST":
			// Kerberoasting attack path
			path := []string{candidate.SamAccountName, "Service Account", "Lateral Movement"}
			bhe.AddAttackPath(path, "Kerberoasting")

			// Add SPN relationships
			for _, spn := range candidate.SPNs {
				bhe.AddSPN(candidate.SamAccountName, spn)
			}
		}

		// Add group memberships
		for _, group := range candidate.MemberOf {
			groupName := extractGroupName(group)
			bhe.AddGroupMembership(candidate.SamAccountName, groupName)
		}
	}

	log.Printf("✅ Generated attack paths from Kerberos analysis")
}

// Helper functions

func extractGroupName(distinguishedName string) string {
	// Extract group name from DN like "CN=Domain Admins,CN=Users,DC=corp,DC=local"
	parts := strings.Split(distinguishedName, ",")
	if len(parts) > 0 {
		return strings.TrimPrefix(parts[0], "CN=")
	}
	return distinguishedName
}

// ExportKerberosToBloodHound exports Kerberos analysis results to BloodHound format
func ExportKerberosToBloodHound(results []krb.Candidate, domain, outputFile string) error {
	exporter := NewBloodHoundExporter(domain)

	// Add users from Kerberos results
	for _, candidate := range results {
		isAdmin := false
		for _, group := range candidate.MemberOf {
			if strings.Contains(strings.ToLower(group), "admin") {
				isAdmin = true
				break
			}
		}

		exporter.AddUser(candidate.SamAccountName, "", isAdmin)
	}

	// Generate attack paths
	exporter.GenerateAttackPaths(results)

	// Export to BloodHound format
	return exporter.ExportToBloodHound(outputFile)
}
