import React from "react";
import { AlertTriangle, FileSearch, Network, Route, ShieldCheck, Waypoints } from "lucide-react";

type Summary = {
  config_source: string | null;
  interfaces: number;
  firewall_rules: number;
  nat_rules: number;
  flows: number;
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

type ExplanationStep = {
  order: number;
  title: string;
  detail: string;
  raw_reference: RawReference | null;
};

type Flow = {
  id: string;
  source: string;
  destination: string;
  service: {
    protocol: string | null;
    ports: string[];
  };
  verdict: "allowed" | "denied" | "unknown" | "ambiguous" | "risky";
  path: string[];
  matched_firewall_rules: string[];
  matched_nat_rules: string[];
  explanation: ExplanationStep[];
};

type Policy = {
  flows: Flow[];
  findings: Finding[];
};

const fallbackSummary: Summary = {
  config_source: null,
  interfaces: 0,
  firewall_rules: 0,
  nat_rules: 0,
  flows: 0,
  findings: 0,
  message: "Backend summary is not loaded yet."
};

const emptyPolicy: Policy = {
  flows: [],
  findings: []
};

export function App() {
  const [summary, setSummary] = React.useState<Summary>(fallbackSummary);
  const [policy, setPolicy] = React.useState<Policy>(emptyPolicy);
  const [selectedFindingId, setSelectedFindingId] = React.useState<string | null>(null);
  const [selectedFlowId, setSelectedFlowId] = React.useState<string | null>(null);
  const [detailMode, setDetailMode] = React.useState<"finding" | "flow">("finding");
  const [apiState, setApiState] = React.useState<"loading" | "ready" | "offline">("loading");

  React.useEffect(() => {
    Promise.all([fetchJson<Summary>("/api/v1/summary"), fetchJson<Policy>("/api/v1/policy")])
      .then(([summaryData, policyData]) => {
        setSummary(summaryData);
        setPolicy(policyData);
        setSelectedFindingId(policyData.findings[0]?.id ?? null);
        setSelectedFlowId(policyData.flows[0]?.id ?? null);
        setDetailMode(policyData.flows.length > 0 ? "flow" : "finding");
        setApiState("ready");
      })
      .catch(() => {
        setApiState("offline");
      });
  }, []);

  const selectedFinding =
    policy.findings.find((finding) => finding.id === selectedFindingId) ?? policy.findings[0] ?? null;
  const selectedFlow = policy.flows.find((flow) => flow.id === selectedFlowId) ?? policy.flows[0] ?? null;

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
        <Metric icon={<Waypoints size={20} />} label="Flows" value={summary.flows} />
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
                  onClick={() => {
                    setSelectedFindingId(finding.id);
                    setDetailMode("finding");
                  }}
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
          {policy.flows.length > 0 ? (
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
                {policy.flows.map((flow) => (
                  <tr
                    className={`flow-row ${flow.id === selectedFlow?.id && detailMode === "flow" ? "selected" : ""}`}
                    key={flow.id}
                    onClick={() => {
                      setSelectedFlowId(flow.id);
                      setDetailMode("flow");
                    }}
                  >
                    <td>{flow.source}</td>
                    <td>{flow.destination}</td>
                    <td>{formatService(flow.service)}</td>
                    <td>
                      <span className={`verdict verdict-${flow.verdict}`}>{flow.verdict}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="empty-state">{summary.message}</div>
          )}
        </Panel>

        <Panel title="Explanation Detail">
          {detailMode === "flow" && selectedFlow ? (
            <div className="detail-stack">
              <div>
                <span className={`verdict verdict-${selectedFlow.verdict}`}>{selectedFlow.verdict}</span>
                <h3>
                  {selectedFlow.source} to {selectedFlow.destination}
                </h3>
              </div>
              <dl>
                <div>
                  <dt>Service</dt>
                  <dd>{formatService(selectedFlow.service)}</dd>
                </div>
                <div>
                  <dt>Path</dt>
                  <dd>{selectedFlow.path.join(" -> ")}</dd>
                </div>
                <div>
                  <dt>Matched Rules</dt>
                  <dd>
                    {selectedFlow.matched_nat_rules.length} NAT,{" "}
                    {selectedFlow.matched_firewall_rules.length} firewall
                  </dd>
                </div>
              </dl>
              <ol className="explanation-steps">
                {selectedFlow.explanation.map((step) => (
                  <li key={`${selectedFlow.id}-${step.order}`}>
                    <strong>{step.title}</strong>
                    <span>{step.detail}</span>
                    {step.raw_reference ? <code>{step.raw_reference.path}</code> : null}
                  </li>
                ))}
              </ol>
            </div>
          ) : selectedFinding ? (
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

function formatService(service: Flow["service"]) {
  const protocol = service.protocol ?? "any";
  const ports = service.ports.length > 0 ? service.ports.join(", ") : "any";
  return `${protocol}/${ports}`;
}

function Panel(props: { title: string; children: React.ReactNode }) {
  return (
    <section className="panel">
      <h2>{props.title}</h2>
      {props.children}
    </section>
  );
}
