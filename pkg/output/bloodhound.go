package output

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/thechosenone-shall-prevail/cold-relay/pkg/reasoning"
)

// BloodHoundNode represents a BloodHound graph node
type BloodHoundNode struct {
	Type       string                 `json:"type"`
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Properties map[string]interface{} `json:"properties"`
}

// BloodHoundEdge represents a BloodHound graph edge
type BloodHoundEdge struct {
	SourceID string `json:"source"`
	TargetID string `json:"target"`
	Type     string `json:"type"`
}

// BloodHoundGraph represents the complete BloodHound graph structure
type BloodHoundGraph struct {
	Meta struct {
		Type           string `json:"type"`
		Version        int    `json:"version"`
		Count          int    `json:"count"`
		GeneratedAt    string `json:"generated_at"`
		CollectionTime string `json:"collection_time"`
	} `json:"meta"`
	Nodes []BloodHoundNode `json:"nodes"`
	Edges []BloodHoundEdge `json:"edges"`
}

// WriteBloodHoundJSON exports the attack graph to BloodHound-compatible JSON format
func WriteBloodHoundJSON(path string, results Results) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("bloodhound JSON path cannot be empty")
	}
	// Ensure directory exists
	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory: %v", err)
		}
	}

	// Convert attack graph to BloodHound format
	bhGraph, err := convertToBloodHoundGraph(results)
	if err != nil {
		return fmt.Errorf("failed to convert to BloodHound format: %v", err)
	}

	// Marshal to JSON with indentation
	data, err := json.MarshalIndent(bhGraph, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}

	// Write to file
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %v", err)
	}

	log.Printf("[+] BloodHound JSON export successful: %s (%d bytes)", path, len(data))

	return nil
}

// convertToBloodHoundGraph converts the attack graph to BloodHound format
func convertToBloodHoundGraph(results Results) (*BloodHoundGraph, error) {
	graph := &BloodHoundGraph{}
	now := time.Now().Format("2006-01-02T15:04:05Z")

	// Set metadata
	graph.Meta.Type = "bloodhound_graph"
	graph.Meta.Version = 4
	graph.Meta.GeneratedAt = now
	graph.Meta.CollectionTime = now

	if results.AttackGraph == nil {
		return graph, nil
	}

	// Convert nodes
	for _, node := range results.AttackGraph.Nodes {
		bhNode := BloodHoundNode{
			Type:       node.Type,
			ID:         node.ID,
			Name:       node.Name,
			Properties: node.Properties,
		}
		graph.Nodes = append(graph.Nodes, bhNode)
	}

	// Convert edges
	for _, edge := range results.AttackGraph.Edges {
		bhEdge := BloodHoundEdge{
			SourceID: edge.From,
			TargetID: edge.To,
			Type:     edge.Type,
		}
		graph.Edges = append(graph.Edges, bhEdge)
	}

	// Update counts
	graph.Meta.Count = len(graph.Nodes)

	return graph, nil
}

// WriteBloodHoundCSV exports the attack graph to BloodHound CSV format (nodes and edges)
func WriteBloodHoundCSV(path string, results Results) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("bloodhound CSV path cannot be empty")
	}
	// Ensure directory exists
	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory: %v", err)
		}
	}

	if results.AttackGraph == nil {
		return fmt.Errorf("no attack graph data available")
	}

	// Write nodes CSV
	nodesPath := path[:len(path)-4] + "_nodes.csv"
	if err := writeNodesCSV(nodesPath, results.AttackGraph.Nodes); err != nil {
		return fmt.Errorf("failed to write nodes CSV: %v", err)
	}

	// Write edges CSV
	edgesPath := path[:len(path)-4] + "_edges.csv"
	if err := writeEdgesCSV(edgesPath, results.AttackGraph.Edges); err != nil {
		return fmt.Errorf("failed to write edges CSV: %v", err)
	}

	log.Printf("[+] BloodHound CSV export successful: %s, %s", nodesPath, edgesPath)

	return nil
}

// writeNodesCSV writes nodes to BloodHound CSV format
func writeNodesCSV(path string, nodes []reasoning.Node) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write header
	header := "NodeID,NodeType,NodeName,Properties\n"
	if _, err := file.WriteString(header); err != nil {
		return err
	}

	// Write nodes
	for _, node := range nodes {
		propsJSON, _ := json.Marshal(node.Properties)
		propsStr := escapeCSV(string(propsJSON))
		line := fmt.Sprintf("%s,%s,%s,%s\n", node.ID, node.Type, node.Name, propsStr)
		if _, err := file.WriteString(line); err != nil {
			return err
		}
	}

	return nil
}

// writeEdgesCSV writes edges to BloodHound CSV format
func writeEdgesCSV(path string, edges []reasoning.Edge) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write header
	header := "SourceID,TargetID,EdgeType\n"
	if _, err := file.WriteString(header); err != nil {
		return err
	}

	// Write edges
	for _, edge := range edges {
		line := fmt.Sprintf("%s,%s,%s\n", edge.From, edge.To, edge.Type)
		if _, err := file.WriteString(line); err != nil {
			return err
		}
	}

	return nil
}

// escapeCSV escapes special characters for CSV format
func escapeCSV(s string) string {
	if containsAny(s, []string{",", "\"", "\n"}) {
		return `"` + replaceAll(s, `"`, `""`) + `"`
	}
	return s
}

func containsAny(s string, chars []string) bool {
	for _, c := range chars {
		for i := 0; i < len(s); i++ {
			match := true
			for j := 0; j < len(c); j++ {
				if i+j >= len(s) || string(s[i+j]) != string(c[j]) {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
	}
	return false
}

func replaceAll(s, old, new string) string {
	result := ""
	for i := 0; i < len(s); i++ {
		if i <= len(s)-len(old) {
			match := true
			for j := 0; j < len(old); j++ {
				if string(s[i+j]) != string(old[j]) {
					match = false
					break
				}
			}
			if match {
				result += new
				i += len(old) - 1
				continue
			}
		}
		result += string(s[i])
	}
	return result
}
