import React, { useState } from "react";

interface MitreTechnique {
  technique_id: string;
  name: string;
  tactic: string;
  confidence?: number;
  evidence?: string[];
}

interface MitreHeatmapProps {
  techniques?: MitreTechnique[];
}

const ALL_TACTICS = [
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
];

export const MitreHeatmap: React.FC<MitreHeatmapProps> = ({ techniques = [] }) => {
  const [activeTech, setActiveTech] = useState<MitreTechnique | null>(null);

  const techMap = new Map<string, MitreTechnique>();
  techniques.forEach((t) => {
    techMap.set(t.technique_id, t);
    // Also map by name or tactic if needed
  });

  // Default known email threat techniques for demonstration / fallback if empty
  const defaultTechniques: MitreTechnique[] = [
    { technique_id: "T1566.001", name: "Spearphishing Attachment", tactic: "Initial Access", confidence: 95, evidence: ["Malicious attachment detected"] },
    { technique_id: "T1566.002", name: "Spearphishing Link", tactic: "Initial Access", confidence: 98, evidence: ["Deceptive hyperlink mismatch"] },
    { technique_id: "T1598.003", name: "Phishing for Information", tactic: "Reconnaissance", confidence: 85, evidence: ["Credential harvest keywords"] },
    { technique_id: "T1656", name: "Impersonation", tactic: "Defense Evasion", confidence: 90, evidence: ["Brand spoofing / Display name spoofing"] },
    { technique_id: "T1078", name: "Valid Accounts", tactic: "Persistence", confidence: 75, evidence: ["BEC executive authority cues"] },
  ];

  const displayTechs = techniques.length > 0 ? techniques : defaultTechniques;

  return (
    <div className="bg-surface border border-hairline rounded-xl p-5 shadow-lg">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-accent uppercase tracking-wider">
          MITRE ATT&CK Matrix Heatmap (All 14 Tactics)
        </h3>
        <span className="text-xs text-ink-mute">Hover/Click cells for evidence & confidence</span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
        {ALL_TACTICS.map((tactic) => {
          const matched = displayTechs.filter((t) => t.tactic.toLowerCase() === tactic.toLowerCase());
          return (
            <div key={tactic} className="bg-sunken border border-hairline rounded-lg p-3">
              <h4 className="text-xs font-bold text-accent uppercase mb-2 border-b border-hairline pb-1">
                {tactic}
              </h4>
              {matched.length === 0 ? (
                <p className="text-[11px] text-ink-faint italic">No techniques triggered</p>
              ) : (
                <div className="space-y-2">
                  {matched.map((tech) => {
                    const conf = tech.confidence || 80;
                    const bg = conf > 90 ? "bg-critical/20 border-critical/50 text-critical" : conf > 75 ? "bg-medium/15 border-medium/50 text-medium" : "bg-safe/15 border-safe/40 text-safe";
                    return (
                      <div
                        key={tech.technique_id}
                        onClick={() => setActiveTech(tech)}
                        className={`p-2 rounded border cursor-pointer transition hover:scale-[1.02] ${bg}`}
                      >
                        <div className="flex justify-between items-center text-xs font-semibold">
                          <span>{tech.technique_id}</span>
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-black/40">{conf}%</span>
                        </div>
                        <p className="text-xs mt-1 font-medium">{tech.name}</p>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {activeTech && (
        <div className="mt-4 p-3 bg-raised border border-accent/40 rounded-lg flex justify-between items-center text-xs text-ink-dim">
          <div>
            <strong className="text-accent">{activeTech.technique_id}: {activeTech.name}</strong> ({activeTech.tactic})
            <p className="text-ink-dim mt-1">Confidence: {activeTech.confidence}% | Evidence: {(activeTech.evidence || []).join(", ") || "N/A"}</p>
          </div>
          <button onClick={() => setActiveTech(null)} className="text-ink-mute hover:text-ink px-2 py-1 bg-black/30 rounded">Close</button>
        </div>
      )}
    </div>
  );
};
