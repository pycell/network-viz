import React from "react";
import { AlertTriangle, FileSearch, Network, Route, ShieldCheck } from "lucide-react";

type Summary = {
  config_source: string | null;
  interfaces: number;
  firewall_rules: number;
  nat_rules: number;
  findings: number;
  message: string;
};

type RawReference = {
  backend: string;
  path: string;
  raw_id: string | null;
};

type Finding = {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  explanation: string;
  confidence: "high" | "medium" | "low";
  raw_references: RawReference[];
};

type Policy = {
  findings: Finding[];
};

const fallbackSummary: Summary = {
  config_source: null,
  interfaces: 0,
  firewall_rules: 0,
  nat_rules: 0,
  findings: 0,
  message: "Backend summary is not loaded yet."
};

const emptyPolicy: Policy = {
  findings: []
};

export function App() {
  const [summary, setSummary] = React.useState<Summary>(fallbackSummary);
  const [policy, setPolicy] = React.useState<Policy>(emptyPolicy);
  const [selectedFindingId, setSelectedFindingId] = React.useState<string | null>(null);
  const [apiState, setApiState] = React.useState<"loading" | "ready" | "offline">("loading");

  React.useEffect(() => {
    Promise.all([fetchJson<Summary>("/api/v1/summary"), fetchJson<Policy>("/api/v1/policy")])
      .then(([summaryData, policyData]) => {
        setSummary(summaryData);
        setPolicy(policyData);
        setSelectedFindingId(policyData.findings[0]?.id ?? null);
        setApiState("ready");
      })
      .catch(() => {
        setApiState("offline");
      });
  }, []);

  const selectedFinding =
    policy.findings.find((finding) => finding.id === selectedFindingId) ?? policy.findings[0] ?? null;

  return (
    <main className="app-shell">
      <header className="top-bar">
        <div>
          <h1>Network Policy Visualization</h1>
          <p>Read-only policy analysis for pfSense, iptables, routing, and NAT.</p>
        </div>
        <span className={`status-pill status-${apiState}`}>
          {apiState === "ready" ? "API connected" : apiState === "loading" ? "Loading" : "API offline"}
        </span>
      </header>

      <section className="summary-grid" aria-label="Policy summary">
        <Metric icon={<FileSearch size={20} />} label="Source" value={summary.config_source ?? "Not loaded"} />
        <Metric icon={<Network size={20} />} label="Interfaces" value={summary.interfaces} />
        <Metric icon={<ShieldCheck size={20} />} label="Firewall Rules" value={summary.firewall_rules} />
        <Metric icon={<Route size={20} />} label="NAT Rules" value={summary.nat_rules} />
        <Metric icon={<AlertTriangle size={20} />} label="Findings" value={summary.findings} />
      </section>

      <section className="workspace-grid">
        <Panel title="Major Flow Map">
          <div className="flow-map">
            <div className="zone">Internet</div>
            <div className="link" />
            <div className="zone firewall">Firewall</div>
            <div className="link" />
            <div className="zone">Internal Zones</div>
          </div>
        </Panel>

        <Panel title="Risk Findings">
          {policy.findings.length > 0 ? (
            <div className="finding-list">
              {policy.findings.map((finding) => (
                <button
                  className={`finding-row ${finding.id === selectedFinding?.id ? "selected" : ""}`}
                  key={finding.id}
                  onClick={() => setSelectedFindingId(finding.id)}
                  type="button"
                >
                  <span className={`severity severity-${finding.severity}`}>{finding.severity}</span>
                  <span>{finding.title}</span>
                </button>
              ))}
            </div>
          ) : (
            <div className="empty-state">{summary.message}</div>
          )}
        </Panel>

        <Panel title="Major Flows">
          <table>
            <thead>
              <tr>
                <th>Source</th>
                <th>Destination</th>
                <th>Service</th>
                <th>Verdict</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>Pending</td>
                <td>Pending</td>
                <td>Pending</td>
                <td>Unknown</td>
              </tr>
            </tbody>
          </table>
        </Panel>

        <Panel title="Explanation Detail">
          {selectedFinding ? (
            <div className="detail-stack">
              <div>
                <span className={`severity severity-${selectedFinding.severity}`}>
                  {selectedFinding.severity}
                </span>
                <h3>{selectedFinding.title}</h3>
              </div>
              <p>{selectedFinding.explanation}</p>
              <dl>
                <div>
                  <dt>Confidence</dt>
                  <dd>{selectedFinding.confidence}</dd>
                </div>
                <div>
                  <dt>Source Reference</dt>
                  <dd>{selectedFinding.raw_references[0]?.path ?? "Unavailable"}</dd>
                </div>
              </dl>
            </div>
          ) : (
            <div className="empty-state">{summary.message}</div>
          )}
        </Panel>
      </section>
    </main>
  );
}

function Metric(props: { icon: React.ReactNode; label: string; value: number | string }) {
  return (
    <article className="metric-card">
      <div className="metric-icon">{props.icon}</div>
      <div>
        <span>{props.label}</span>
        <strong>{props.value}</strong>
      </div>
    </article>
  );
}

function fetchJson<T>(url: string): Promise<T> {
  return fetch(url).then((response) => {
    if (!response.ok) {
      throw new Error(`Unexpected status ${response.status}`);
    }
    return response.json() as Promise<T>;
  });
}

function Panel(props: { title: string; children: React.ReactNode }) {
  return (
    <section className="panel">
      <h2>{props.title}</h2>
      {props.children}
    </section>
  );
}
