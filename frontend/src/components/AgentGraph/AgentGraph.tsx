import { useEffect, useMemo, useRef } from "react";
import type cytoscape from "cytoscape";
import CytoscapeComponent from "react-cytoscapejs";
import { useShieldStore } from "../../store/useShieldStore";
import type { AgentEdge, AgentNode, AgentStatus, TrustLevel } from "../../types";

type Stylesheet = {
  selector: string;
  style: Record<string, string | number>;
};

interface AgentGraphProps {
  height?: string;
  className?: string;
}

const STATUS_COLORS: Record<AgentStatus, string> = {
  clean: "#06b6d4",
  suspicious: "#f59e0b",
  compromised: "#ef4444",
  unknown: "#6b7280",
};

const TRUST_EDGE_COLORS: Record<TrustLevel, string> = {
  TRUSTED: "#06b6d4",
  INTERNAL: "#3b82f6",
  EXTERNAL: "#f59e0b",
  UNTRUSTED: "#ef4444",
};

const layoutConfig: cytoscape.LayoutOptions = {
  name: "cose",
  animate: true,
  randomize: false,
  nodeRepulsion: 4000,
  idealEdgeLength: 150,
  edgeElasticity: 100,
  gravity: 0.25,
  numIter: 1000,
  fit: true,
  padding: 30,
};

const cytoscapeStylesheet: Stylesheet[] = [
  {
    selector: "node",
    style: {
      "background-color": "data(bg)",
      label: "data(label)",
      color: "#f9fafb",
      "font-size": 10,
      "text-valign": "center",
      "text-halign": "center",
      width: 44,
      height: 44,
      "border-width": 2,
      "border-color": "#1f2937",
      "transition-property": "background-color border-color",
      "transition-duration": "0.3s",
    },
  },
  {
    selector: "node:selected",
    style: {
      "border-color": "#f9fafb",
      "border-width": 3,
    },
  },
  {
    selector: "node[threatCount > 0]",
    style: {
      "border-color": "#ef4444",
    },
  },
  {
    selector: "edge",
    style: {
      "line-color": "data(color)",
      "target-arrow-color": "data(color)",
      "target-arrow-shape": "triangle",
      "curve-style": "bezier",
      width: 2,
      opacity: 0.7,
    },
  },
  {
    selector: "edge:selected",
    style: {
      width: 3,
      opacity: 1,
    },
  },
];

const toElements = (
  agentsById: Record<string, AgentNode>,
  edges: AgentEdge[],
): cytoscape.ElementDefinition[] => {
  const nodes: cytoscape.ElementDefinition[] = Object.values(agentsById).map((agent) => ({
    data: {
      id: agent.agent_id,
      label: agent.agent_id.slice(0, 8),
      status: agent.status,
      threatCount: agent.threat_count,
      bg: STATUS_COLORS[agent.status],
    },
  }));

  const graphEdges: cytoscape.ElementDefinition[] = edges.map((edge) => ({
    data: {
      id: `${edge.source_agent_id}__${edge.target_agent_id}`,
      source: edge.source_agent_id,
      target: edge.target_agent_id,
      trust: edge.last_trust_level,
      color: TRUST_EDGE_COLORS[edge.last_trust_level],
    },
  }));

  return [...nodes, ...graphEdges];
};

export function AgentGraph({
  height = "500px",
  className = "",
}: AgentGraphProps): JSX.Element {
  const agents = useShieldStore((state) => state.agents);
  const edges = useShieldStore((state) => state.edges);
  const wsConnected = useShieldStore((state) => state.wsConnected);
  const setSelectedAgent = useShieldStore((state) => state.setSelectedAgent);
  const cyRef = useRef<cytoscape.Core | null>(null);

  const agentCount = useMemo(() => Object.keys(agents).length, [agents]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) {
      return;
    }

    const newElements = toElements(agents, edges);
    cy.json({ elements: newElements });
    cy.layout(layoutConfig).run();
  }, [agents, edges]);

  const handleCyInit = (cy: cytoscape.Core): void => {
    cyRef.current = cy;

    cy.off("tap");
    cy.off("tap", "node");

    cy.on("tap", "node", (event: cytoscape.EventObject) => {
      setSelectedAgent(event.target.id());
    });

    cy.on("tap", (event: cytoscape.EventObject) => {
      if (event.target === cy) {
        setSelectedAgent(null);
      }
    });

    const newElements = toElements(agents, edges);
    cy.json({ elements: newElements });
    cy.layout(layoutConfig).run();
  };

  return (
    <section
      className={`flex w-full flex-col overflow-hidden rounded-md border border-shield-border bg-shield-bg ${className}`}
      style={{ height }}
    >
      <div className="flex items-center justify-between border-b border-shield-border p-3">
        <h2 className="text-sm font-medium text-gray-300">Agent Trust Network</h2>
        <div className="flex items-center gap-3">
          <span className="rounded-full border border-shield-border bg-shield-surface px-2 py-0.5 text-xs text-shield-subtext">
            {agentCount} agents
          </span>
          <div className="flex items-center gap-1.5 text-xs text-shield-subtext">
            <span
              className={`h-2 w-2 rounded-full ${wsConnected ? "bg-shield-accent" : "bg-shield-danger"}`}
            />
            {wsConnected ? "live" : "offline"}
          </div>
        </div>
      </div>

      {agentCount === 0 ? (
        <div className="flex flex-1 items-center justify-center">
          <p className="text-sm italic text-gray-500">
            No agents connected - start a demo to see the trust graph
          </p>
        </div>
      ) : (
        <div className="flex-1">
          <CytoscapeComponent
            elements={[]}
            stylesheet={cytoscapeStylesheet}
            layout={layoutConfig}
            style={{ width: "100%", height: "100%" }}
            cy={(cy: cytoscape.Core) => {
              handleCyInit(cy);
            }}
          />
        </div>
      )}

      <div className="flex min-h-[12px] items-center justify-center gap-4 border-t border-shield-border px-3 py-1 text-[11px] text-shield-subtext">
        <span className="flex items-center gap-1">
          <span className="h-2 w-2 rounded-full" style={{ backgroundColor: STATUS_COLORS.clean }} />
          clean
        </span>
        <span className="flex items-center gap-1">
          <span
            className="h-2 w-2 rounded-full"
            style={{ backgroundColor: STATUS_COLORS.suspicious }}
          />
          suspicious
        </span>
        <span className="flex items-center gap-1">
          <span
            className="h-2 w-2 rounded-full"
            style={{ backgroundColor: STATUS_COLORS.compromised }}
          />
          compromised
        </span>
        <span className="flex items-center gap-1">
          <span className="h-2 w-2 rounded-full" style={{ backgroundColor: STATUS_COLORS.unknown }} />
          unknown
        </span>
      </div>
    </section>
  );
}