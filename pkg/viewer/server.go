package viewer

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/thechosenone-shall-prevail/cold-relay/pkg/output"
)

type GraphPayload struct {
	Meta       map[string]interface{} `json:"meta"`
	Nodes      []GraphNode            `json:"nodes"`
	Links      []GraphLink            `json:"links"`
	NodeTypes  []string               `json:"node_types"`
	EdgeTypes  []string               `json:"edge_types"`
	RawResults output.Results         `json:"raw_results"`
}

type GraphNode struct {
	ID         string                 `json:"id"`
	Label      string                 `json:"label"`
	Type       string                 `json:"type"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type GraphLink struct {
	Source     string   `json:"source"`
	Target     string   `json:"target"`
	Type       string   `json:"type"`
	Validation string   `json:"validation"`
	Evidence   []string `json:"evidence,omitempty"`
}

func Serve(resultsPath string, port int) error {
	payload, err := loadPayload(resultsPath)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(indexHTML))
	})
	mux.HandleFunc("/api/graph", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
	})

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	fmt.Printf("[+] Graph viewer ready at http://%s\n", addr)
	fmt.Printf("[*] Loaded graph with %d nodes and %d links from %s\n", len(payload.Nodes), len(payload.Links), resultsPath)
	return http.ListenAndServe(addr, mux)
}

func loadPayload(path string) (GraphPayload, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return GraphPayload{}, fmt.Errorf("read results file: %w", err)
	}

	var results output.Results
	if err := json.Unmarshal(data, &results); err != nil {
		return GraphPayload{}, fmt.Errorf("parse results JSON: %w", err)
	}
	if results.AttackGraph == nil {
		return GraphPayload{}, fmt.Errorf("results file has no attack_graph section")
	}

	nodes := make([]GraphNode, 0, len(results.AttackGraph.Nodes))
	links := make([]GraphLink, 0, len(results.AttackGraph.Edges))
	nodeTypeSet := make(map[string]bool)
	edgeTypeSet := make(map[string]bool)

	for _, node := range results.AttackGraph.Nodes {
		nodes = append(nodes, GraphNode{
			ID:         node.ID,
			Label:      firstNonEmpty(node.Name, node.ID),
			Type:       firstNonEmpty(node.Type, "unknown"),
			Properties: node.Properties,
		})
		nodeTypeSet[firstNonEmpty(node.Type, "unknown")] = true
	}
	for _, edge := range results.AttackGraph.Edges {
		links = append(links, GraphLink{
			Source:     edge.From,
			Target:     edge.To,
			Type:       firstNonEmpty(edge.Type, "related_to"),
			Validation: firstNonEmpty(edge.Validation, "likely"),
			Evidence:   edge.Evidence,
		})
		edgeTypeSet[firstNonEmpty(edge.Type, "related_to")] = true
	}

	nodeTypes := keysSorted(nodeTypeSet)
	edgeTypes := keysSorted(edgeTypeSet)

	return GraphPayload{
		Meta: map[string]interface{}{
			"schema_version": results.SchemaVersion,
			"domain":         results.Domain.Name,
			"total_nodes":    len(nodes),
			"total_links":    len(links),
		},
		Nodes:      nodes,
		Links:      links,
		NodeTypes:  nodeTypes,
		EdgeTypes:  edgeTypes,
		RawResults: results,
	}, nil
}

func keysSorted(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

const indexHTML = `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Cold Relay Graph Viewer</title>
  <style>
    html, body { height: 100%; margin: 0; font-family: Segoe UI, Arial, sans-serif; background: #0b0f16; color: #e6edf3; }
    #app { display: grid; grid-template-columns: 1fr 420px; height: 100%; }
    #graph { width: 100%; height: 100%; }
    #sidebar { border-left: 1px solid #1f2937; background: #111827; padding: 12px; overflow: auto; }
    .title { font-size: 16px; font-weight: 600; margin-bottom: 10px; }
    .meta { font-size: 12px; color: #9ca3af; margin-bottom: 12px; }
    .box { border: 1px solid #1f2937; border-radius: 8px; padding: 10px; margin-bottom: 10px; background: #0f172a; }
    .label { font-size: 11px; color: #94a3b8; text-transform: uppercase; margin-bottom: 4px; }
    .value { font-size: 13px; word-break: break-word; }
    .row { display: flex; gap: 8px; margin-bottom: 8px; }
    input, select { flex: 1; background: #0b1220; color: #e6edf3; border: 1px solid #334155; border-radius: 6px; padding: 6px; }
    .list { max-height: 180px; overflow: auto; font-size: 12px; color: #cbd5e1; }
    .legend-item { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; font-size: 12px; color: #cbd5e1; }
    .dot { width: 10px; height: 10px; border-radius: 50%; border: 1px solid #111827; }
    .muted { color: #94a3b8; }
    pre { margin: 0; }
  </style>
</head>
<body>
  <div id="app">
    <div id="graph"></div>
    <div id="sidebar">
      <div class="title">Cold Relay 3D Graph</div>
      <div id="meta" class="meta">Loading...</div>
      <div class="row">
        <input id="search" placeholder="Search node label..." />
      </div>
      <div class="row">
        <select id="typeFilter"><option value="">All node types</option></select>
        <select id="edgeFilter"><option value="">All edge types</option></select>
      </div>
      <div class="box">
        <div class="label">Node Color Legend</div>
        <div id="legend" class="list"></div>
      </div>
      <div class="box">
        <div class="label">Selected Node</div>
        <div id="selectedName" class="value">Click a node to inspect details.</div>
      </div>
      <div class="box">
        <div class="label">Type</div>
        <div id="selectedType" class="value">-</div>
      </div>
      <div class="box">
        <div class="label">Identity & Properties</div>
        <pre id="selectedProps" class="value" style="white-space: pre-wrap;"></pre>
      </div>
      <div class="box">
        <div class="label">Permissions / Capability Hints</div>
        <div id="permissions" class="list muted"></div>
      </div>
      <div class="box">
        <div class="label">Evidence & What To Do Next</div>
        <div id="actions" class="list muted"></div>
      </div>
      <div class="box">
        <div class="label">Connected Relationships</div>
        <div id="connected" class="list"></div>
      </div>
    </div>
  </div>
  <script src="https://unpkg.com/3d-force-graph"></script>
  <script>
    const baseColors = {
      principal: '#4f46e5',
      group: '#16a34a',
      service: '#0ea5e9',
      finding: '#f97316',
      share: '#a855f7',
      secret: '#ef4444',
      domain: '#facc15',
      target: '#22c55e',
      spn: '#06b6d4',
      gpo: '#8b5cf6',
      trust: '#f59e0b',
      directory_object: '#3b82f6',
      privilege: '#dc2626',
      delegation_target: '#f43f5e',
      delegation_account: '#e879f9',
      replication_principal: '#ef4444',
      certificate_template: '#14b8a6',
      dns_zone_transfer: '#fb7185',
      session_state: '#84cc16',
      default: '#64748b'
    };
    const fallbackPalette = ['#64748b','#06b6d4','#22c55e','#f59e0b','#8b5cf6','#e11d48','#14b8a6','#f97316','#3b82f6','#a855f7'];
    const typeColors = {};
    const byTypeColor = t => typeColors[t] || baseColors[t] || baseColors.default;
    let payload;
    let fullData;
    let nodeById = {};
    const PERF_NODE_LIMIT = 650;
    const PERF_LINK_LIMIT = 1800;
    const graph = ForceGraph3D()(document.getElementById('graph'))
      .backgroundColor('#0b0f16')
      .nodeLabel(n => n.label + ' (' + n.type + ')')
      .nodeColor(n => byTypeColor(n.type))
      .linkColor(() => '#64748b')
      .linkOpacity(0.55)
      .nodeRelSize(6)
      .nodeResolution(6)
      .linkResolution(3)
      .warmupTicks(20)
      .cooldownTicks(80)
      .d3AlphaDecay(0.04)
      .d3VelocityDecay(0.35)
      .onNodeClick(node => focusNode(node));

    function normalizeRef(ref) {
      if (ref && typeof ref === 'object' && ref.id) return ref.id;
      return ref;
    }

    function assignTypeColors(types) {
      let i = 0;
      types.forEach(t => {
        if (baseColors[t]) {
          typeColors[t] = baseColors[t];
        } else {
          typeColors[t] = fallbackPalette[i % fallbackPalette.length];
          i++;
        }
      });
    }

    function renderLegend() {
      const box = document.getElementById('legend');
      box.innerHTML = '';
      payload.node_types.forEach(t => {
        const row = document.createElement('div');
        row.className = 'legend-item';
        const dot = document.createElement('div');
        dot.className = 'dot';
        dot.style.background = byTypeColor(t);
        const text = document.createElement('span');
        text.textContent = t;
        row.appendChild(dot);
        row.appendChild(text);
        box.appendChild(row);
      });
    }

    function renderFilters() {
      const type = document.getElementById('typeFilter');
      payload.node_types.forEach(t => {
        const o = document.createElement('option');
        o.value = t; o.textContent = t; type.appendChild(o);
      });
      const edge = document.getElementById('edgeFilter');
      payload.edge_types.forEach(t => {
        const o = document.createElement('option');
        o.value = t; o.textContent = t; edge.appendChild(o);
      });
    }

    function applyFilters() {
      const q = document.getElementById('search').value.toLowerCase().trim();
      const tf = document.getElementById('typeFilter').value;
      const ef = document.getElementById('edgeFilter').value;

      const nodeSet = new Set(fullData.nodes
        .filter(n => (!tf || n.type === tf) && (!q || n.label.toLowerCase().includes(q)))
        .map(n => n.id));

      const links = fullData.links.filter(l => {
        const s = normalizeRef(l.source);
        const t = normalizeRef(l.target);
        return (!ef || l.type === ef) && nodeSet.has(s) && nodeSet.has(t);
      });
      const nodes = fullData.nodes.filter(n => nodeSet.has(n.id));
      graph.graphData(optimizeForRender(nodes, links));
    }

    function optimizeForRender(nodes, links) {
      if (nodes.length <= PERF_NODE_LIMIT && links.length <= PERF_LINK_LIMIT) {
        return { nodes, links };
      }
      const degree = {};
      links.forEach(l => {
        const s = normalizeRef(l.source);
        const t = normalizeRef(l.target);
        degree[s] = (degree[s] || 0) + 1;
        degree[t] = (degree[t] || 0) + 1;
      });

      const ranked = [...nodes].sort((a, b) => (degree[b.id] || 0) - (degree[a.id] || 0));
      const keptNodes = ranked.slice(0, Math.min(PERF_NODE_LIMIT, ranked.length));
      const keepSet = new Set(keptNodes.map(n => n.id));

      const keptLinks = [];
      for (const l of links) {
        if (keptLinks.length >= PERF_LINK_LIMIT) break;
        const s = normalizeRef(l.source);
        const t = normalizeRef(l.target);
        if (keepSet.has(s) && keepSet.has(t)) keptLinks.push(l);
      }
      return { nodes: keptNodes, links: keptLinks };
    }

    function candidateHintsForNode(node) {
      const candidates = (payload.raw_results && payload.raw_results.candidates) || [];
      const id = (node.id || '').toLowerCase();
      const label = (node.label || '').toLowerCase();
      return candidates.filter(c => {
        const sam = (c.SamAccountName || '').toLowerCase();
        return sam && (label.includes(sam) || id.includes(sam));
      });
    }

    function renderPermissions(node, connected) {
      const out = [];
      const props = node.properties || {};
      if (typeof props.disabled === 'boolean') out.push('Account disabled: ' + props.disabled);
      if (typeof props.preauth_not_needed === 'boolean') out.push('Pre-auth not needed: ' + props.preauth_not_needed);
      if (typeof props.spn_count === 'number') out.push('SPN count: ' + props.spn_count);
      connected.forEach(r => {
        if (r.type && (r.type.includes('can_') || r.type.includes('has_') || r.type.includes('member_of') || r.type.includes('delegat') || r.type.includes('replication'))) {
          out.push(r.type + ' (' + (r.validation || 'n/a') + ')');
        }
      });
      return [...new Set(out)];
    }

    function renderActions(node, candidateHints, connected) {
      const out = [];
      candidateHints.forEach(c => {
        (c.Evidence || []).forEach(e => out.push('Evidence: ' + e));
        (c.Blockers || []).forEach(b => out.push('Blocker: ' + b));
        (c.NextActions || []).forEach(a => out.push('Next: ' + a));
      });
      connected.forEach(r => {
        (r.evidence || []).forEach(e => out.push('Relationship evidence: ' + e));
      });
      return [...new Set(out)].slice(0, 80);
    }

    function renderList(targetId, items, emptyText) {
      const el = document.getElementById(targetId);
      el.innerHTML = '';
      if (!items || items.length === 0) {
        const item = document.createElement('div');
        item.textContent = emptyText;
        item.className = 'muted';
        el.appendChild(item);
        return;
      }
      items.forEach(text => {
        const row = document.createElement('div');
        row.textContent = text;
        el.appendChild(row);
      });
    }

    function focusNode(node) {
      document.getElementById('selectedName').textContent = node.label + ' [' + node.id + ']';
      document.getElementById('selectedType').textContent = node.type || '-';
      document.getElementById('selectedProps').textContent = JSON.stringify(node.properties || {}, null, 2);
      const rels = fullData.links.filter(l => normalizeRef(l.source) === node.id || normalizeRef(l.target) === node.id);
      const relText = rels.map(r => {
        const s = normalizeRef(r.source);
        const t = normalizeRef(r.target);
        const sLabel = (nodeById[s] && nodeById[s].label) ? nodeById[s].label : s;
        const tLabel = (nodeById[t] && nodeById[t].label) ? nodeById[t].label : t;
        return sLabel + ' --(' + r.type + '/' + r.validation + ')-> ' + tLabel;
      });
      renderList('connected', relText, 'No related edges found for this node.');

      const hints = candidateHintsForNode(node);
      const perm = renderPermissions(node, rels);
      const actions = renderActions(node, hints, rels);
      renderList('permissions', perm, 'No explicit permission/capability hints from current evidence.');
      renderList('actions', actions, 'No direct evidence/action hints mapped. Inspect related finding nodes.');

      const distance = 130;
      const distRatio = 1 + distance / Math.hypot(node.x, node.y, node.z);
      graph.cameraPosition(
        { x: node.x * distRatio, y: node.y * distRatio, z: node.z * distRatio },
        node,
        900
      );
    }

    fetch('/api/graph')
      .then(r => r.json())
      .then(data => {
        payload = data;
        fullData = { nodes: data.nodes, links: data.links };
        data.nodes.forEach(n => { nodeById[n.id] = n; });
        assignTypeColors(data.node_types || []);
        document.getElementById('meta').textContent =
          'Domain: ' + (data.meta.domain || '-') + ' | Nodes: ' + data.meta.total_nodes + ' | Links: ' + data.meta.total_links;
        renderFilters();
        renderLegend();
        graph.graphData(optimizeForRender(fullData.nodes, fullData.links));
        document.getElementById('search').addEventListener('input', applyFilters);
        document.getElementById('typeFilter').addEventListener('change', applyFilters);
        document.getElementById('edgeFilter').addEventListener('change', applyFilters);
      })
      .catch(err => {
        document.getElementById('meta').textContent = 'Failed loading graph payload: ' + err;
      });
  </script>
</body>
</html>`
