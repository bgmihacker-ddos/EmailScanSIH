import React, { useEffect, useRef, useState } from "react";
import { Network } from "vis-network/standalone";

interface Node {
  id: string;
  label: string;
  group: string;
  title?: string;
  color?: string;
}

interface Edge {
  from: string;
  to: string;
  label?: string;
}

interface EvidenceGraphProps {
  graph?: {
    nodes?: Array<{ id: string; type: string; value: string; metadata?: any }>;
    edges?: Array<{ source: string; target: string; relationship: string }>;
  };
  evidenceGraph?: {
    nodes?: Array<{ id: string; type: string; value: string; metadata?: any }>;
    edges?: Array<{ source: string; target: string; relationship: string }>;
  };
  analysisData?: any;
}

export const EvidenceGraph: React.FC<EvidenceGraphProps> = ({ graph, evidenceGraph, analysisData }) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const [selectedNode, setSelectedNode] = useState<any>(null);

  useEffect(() => {
    if (!containerRef.current) return;

    // Build nodes & edges from props or fallback to analysisData
    const rawNodes = (graph || evidenceGraph)?.nodes || [];
    const rawEdges = (graph || evidenceGraph)?.edges || [];

    if (rawNodes.length === 0 && analysisData) {
      // Build from analysis data
      const nodes: Node[] = [];
      const edges: Edge[] = [];

      const emailId = `email:${analysisData.analysis_id || "target"}`;
      nodes.push({ id: emailId, label: analysisData.subject || "Email Analysis", group: "email", color: "#4C9EEB" });

      const sender = analysisData.sender?.address || analysisData.from;
      if (sender) {
        const senderId = `sender:${sender}`;
        nodes.push({ id: senderId, label: sender, group: "sender", color: "#3ECF8E" });
        edges.push({ from: emailId, to: senderId, label: "sent_by" });
      }

      const iocs = analysisData.ioc_extraction || analysisData.iocs || {};
      (iocs.domains || []).forEach((d: string) => {
        const id = `domain:${d}`;
        nodes.push({ id, label: d, group: "domain", color: "#E8B44A" });
        edges.push({ from: emailId, to: id, label: "mentions_domain" });
      });

      (iocs.ip_addresses || iocs.ips || []).forEach((ip: string) => {
        const id = `ip:${ip}`;
        nodes.push({ id, label: ip, group: "ip", color: "#F4586B" });
        edges.push({ from: emailId, to: id, label: "references_ip" });
      });

      (iocs.urls || []).forEach((u: string) => {
        const shortU = u.length > 30 ? u.substring(0, 27) + "..." : u;
        const id = `url:${u}`;
        nodes.push({ id, label: shortU, title: u, group: "url", color: "#F0794A" });
        edges.push({ from: emailId, to: id, label: "contains_url" });
      });

      renderNetwork(nodes, edges);
    } else {
      const nodes: Node[] = rawNodes.map((n) => ({
        id: n.id || `${n.type}:${n.value}`,
        label: n.value || n.id,
        group: n.type || "node",
        color: getColorForType(n.type),
      }));
      const edges: Edge[] = rawEdges.map((e) => ({
        from: e.source,
        to: e.target,
        label: e.relationship,
      }));
      renderNetwork(nodes, edges);
    }
  }, [evidenceGraph, analysisData]);

  const renderNetwork = (nodes: Node[], edges: Edge[]) => {
    if (!containerRef.current) return;
    const data = {
      nodes,
      edges,
    };
    const options = {
      nodes: {
        shape: "dot",
        size: 16,
        font: { color: "#E9EDF4", size: 12 },
        borderWidth: 2,
      },
      edges: {
        width: 1.5,
        color: { color: "#454F60", highlight: "#4C9EEB" },
        font: { color: "#A6B0C2", size: 10, align: "middle" },
        arrows: { to: { enabled: true, scaleFactor: 0.5 } },
      },
      physics: {
        barnesHut: { gravitationalConstant: -2000, centralGravity: 0.3, springLength: 90 },
      },
      interaction: { hover: true, zoomView: true, dragNodes: true },
    };

    const network = new Network(containerRef.current, data, options);
    network.on("click", (params: any) => {
      if (params.nodes.length > 0) {
        setSelectedNode(params.nodes[0]);
      }
    });
  };

  const getColorForType = (type: string) => {
    switch (type) {
      case "email": return "#4C9EEB";
      case "sender": return "#3ECF8E";
      case "domain": return "#E8B44A";
      case "ip": return "#F4586B";
      case "url": return "#F0794A";
      default: return "#6B7689";
    }
  };

  return (
    <div className="bg-surface border border-hairline rounded-xl p-4 shadow-lg">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-accent uppercase tracking-wider">
          Interactive Evidence & IOC Network Graph
        </h3>
        <span className="text-xs text-ink-mute">Drag nodes to rearrange • Scroll to zoom</span>
      </div>
      <div ref={containerRef} className="w-full h-[450px] rounded-lg bg-sunken border border-hairline" />
      {selectedNode && (
        <div className="mt-2 p-2 bg-raised rounded text-xs text-ink-dim flex justify-between items-center">
          <span>Selected Node: <strong className="text-accent">{selectedNode}</strong></span>
          <button onClick={() => setSelectedNode(null)} className="text-ink-mute hover:text-ink">✕</button>
        </div>
      )}
    </div>
  );
};
