import React from "react";
import {
  AlertTriangle,
  FileSearch,
  Info,
  Network,
  Route,
  ShieldCheck,
  Upload,
  Waypoints
} from "lucide-react";

type SourceMode = "pfsense-xml" | "pfsense-api" | "iptables-local" | "iptables-ssh";

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
  source: { backend: string; name: string } | null;
  interfaces: unknown[];
  firewall_rules: unknown[];
  nat_rules: unknown[];
  routes: unknown[];
  flows: Flow[];
  findings: Finding[];
  message?: string;
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
  source: null,
  interfaces: [],
  firewall_rules: [],
  nat_rules: [],
  routes: [],
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
  const [sourceMode, setSourceMode] = React.useState<SourceMode>("pfsense-xml");
  const [sourceStatus, setSourceStatus] = React.useState("No manual source selected.");
  const [loadingSource, setLoadingSource] = React.useState(false);

  React.useEffect(() => {
    Promise.all([fetchJson<Summary>("/api/v1/summary"), fetchJson<Policy>("/api/v1/policy")])
      .then(([summaryData, policyData]) => {
        setSummary(summaryData);
        setPolicy(policyData);
        selectInitialDetail(policyData, setSelectedFindingId, setSelectedFlowId, setDetailMode);
        setApiState("ready");
      })
      .catch(() => {
        setApiState("offline");
      });
  }, []);

  const selectedFinding =
    policy.findings.find((finding) => finding.id === selectedFindingId) ?? policy.findings[0] ?? null;
  const selectedFlow = policy.flows.find((flow) => flow.id === selectedFlowId) ?? policy.flows[0] ?? null;

  function applyPolicy(nextPolicy: Policy, message: string) {
    setPolicy(nextPolicy);
    setSummary(summaryFromPolicy(nextPolicy, message));
    setSourceStatus(message);
    selectInitialDetail(nextPolicy, setSelectedFindingId, setSelectedFlowId, setDetailMode);
  }

  async function handlePfsenseXmlUpload(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const file = fileFromForm(event.currentTarget, "pfsense_xml");
    if (!file) {
      setSourceStatus("Choose a pfSense XML file.");
      return;
    }
    await submitSource(async () => {
      const content = await file.text();
      const nextPolicy = await postJson<Policy>("/api/v1/policy/pfsense/xml", {
        filename: file.name,
        content
      });
      applyPolicy(nextPolicy, `Loaded ${file.name}.`);
    });
  }

  async function handleIptablesLocalUpload(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const iptablesSave = fileFromForm(form, "iptables_save");
    if (!iptablesSave) {
      setSourceStatus("Choose an iptables-save file.");
      return;
    }
    await submitSource(async () => {
      const nextPolicy = await postJson<Policy>("/api/v1/policy/iptables/local", {
        filename: iptablesSave.name,
        iptables_save: await iptablesSave.text(),
        ip_route: await optionalFileText(form, "ip_route"),
        ip_rule: await optionalFileText(form, "ip_rule"),
        ip_addr: await optionalFileText(form, "ip_addr")
      });
      applyPolicy(nextPolicy, `Loaded ${iptablesSave.name}.`);
    });
  }

  async function handleCredentialedSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);
    const endpoint =
      sourceMode === "pfsense-api" ? "/api/v1/policy/pfsense/api" : "/api/v1/policy/iptables/ssh";
    await submitSource(async () => {
      await postJson<Policy>(endpoint, {
        host: String(formData.get("host") ?? ""),
        username: String(formData.get("username") ?? ""),
        password: String(formData.get("password") ?? ""),
        api_token: String(formData.get("api_token") ?? "")
      });
    });
  }

  async function submitSource(action: () => Promise<void>) {
    setLoadingSource(true);
    try {
      await action();
      setApiState("ready");
    } catch (error) {
      setSourceStatus(error instanceof Error ? error.message : "Source load failed.");
    } finally {
      setLoadingSource(false);
    }
  }

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

      <section className="source-panel" aria-label="Policy source">
        <div className="source-tabs">
          <SourceButton active={sourceMode === "pfsense-xml"} onClick={() => setSourceMode("pfsense-xml")}>
            pfSense XML
          </SourceButton>
          <SourceButton active={sourceMode === "pfsense-api"} onClick={() => setSourceMode("pfsense-api")}>
            pfSense API
          </SourceButton>
          <SourceButton
            active={sourceMode === "iptables-local"}
            onClick={() => setSourceMode("iptables-local")}
          >
            iptables Local
          </SourceButton>
          <SourceButton active={sourceMode === "iptables-ssh"} onClick={() => setSourceMode("iptables-ssh")}>
            iptables SSH
          </SourceButton>
        </div>

        {sourceMode === "pfsense-xml" ? (
          <form className="source-form" onSubmit={handlePfsenseXmlUpload}>
            <label>
              XML file
              <input accept=".xml,text/xml,application/xml" name="pfsense_xml" type="file" />
            </label>
            <button disabled={loadingSource} type="submit">
              <Upload size={16} />
              Load
            </button>
          </form>
        ) : null}

        {sourceMode === "iptables-local" ? (
          <>
            <details className="source-help">
              <summary>
                <Info size={16} />
                Commands and expected files
              </summary>
              <div className="command-grid">
                <code>sudo iptables-save &gt; iptables-save.txt</code>
                <span>Upload as iptables-save. This is required.</span>
                <code>ip route &gt; ip-route.txt</code>
                <span>Upload as ip route. This adds routing context.</span>
                <code>ip rule &gt; ip-rule.txt</code>
                <span>Upload as ip rule. This adds policy-routing context.</span>
                <code>ip -o -4 addr show &gt; ip-addr.txt</code>
                <span>Upload as ip addr. This adds interface and address inventory.</span>
              </div>
            </details>
            <form className="source-form source-form-wide" onSubmit={handleIptablesLocalUpload}>
              <label>
                iptables-save
                <input name="iptables_save" type="file" />
              </label>
              <label>
                ip route
                <input name="ip_route" type="file" />
              </label>
              <label>
                ip rule
                <input name="ip_rule" type="file" />
              </label>
              <label>
                ip addr
                <input name="ip_addr" type="file" />
              </label>
              <button disabled={loadingSource} type="submit">
                <Upload size={16} />
                Load
              </button>
            </form>
          </>
        ) : null}

        {sourceMode === "pfsense-api" || sourceMode === "iptables-ssh" ? (
          <form className="source-form source-form-wide" onSubmit={handleCredentialedSubmit}>
            <label>
              Host
              <input name="host" placeholder="192.0.2.10" type="text" />
            </label>
            <label>
              User
              <input name="username" placeholder="admin" type="text" />
            </label>
            {sourceMode === "pfsense-api" ? (
              <label>
                API token
                <input name="api_token" type="password" />
              </label>
            ) : (
              <label>
                Password
                <input name="password" type="password" />
              </label>
            )}
            <button disabled={loadingSource} type="submit">
              Check
            </button>
          </form>
        ) : null}

        <div className="source-status">{loadingSource ? "Loading source..." : sourceStatus}</div>
      </section>

      <section className="summary-grid" aria-label="Policy summary">
        <Metric icon={<FileSearch size={20} />} label="Source" value={summary.config_source ?? "Not loaded"} />
        <Metric icon={<Network size={20} />} label="Interfaces" value={summary.interfaces} />
        <Metric icon={<ShieldCheck size={20} />} label="Firewall Rules" value={summary.firewall_rules} />
        <Metric icon={<Route size={20} />} label="NAT Rules" value={summary.nat_rules} />
        <Metric icon={<Waypoints size={20} />} label="Flows" value={summary.flows} />
        <Metric icon={<AlertTriangle size={20} />} label="Findings" value={summary.findings} />
      </section>

      <section className="workspace-grid">
        <Panel title="Major Flow Map" hint="Flow verdicts and busiest paths">
          {policy.flows.length > 0 ? (
            <FlowMap
              flows={policy.flows}
              onSelect={(flowId) => {
                setSelectedFlowId(flowId);
                setDetailMode("flow");
              }}
            />
          ) : (
            <div className="empty-state">{summary.message}</div>
          )}
        </Panel>

        <Panel title="Risk Findings" hint="Scrollable">
          {policy.findings.length > 0 ? (
            <div className="finding-list scroll-panel">
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

        <Panel title="Major Flows" hint="Scrollable">
          {policy.flows.length > 0 ? (
            <div className="table-scroll scroll-panel">
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
                      className={`flow-row ${
                        flow.id === selectedFlow?.id && detailMode === "flow" ? "selected" : ""
                      }`}
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
            </div>
          ) : (
            <div className="empty-state">{summary.message}</div>
          )}
        </Panel>

        <Panel title="Explanation Detail" hint="Technical steps and rule story">
          {detailMode === "flow" && selectedFlow ? (
            <FlowDetail flow={selectedFlow} />
          ) : selectedFinding ? (
            <FindingDetail finding={selectedFinding} />
          ) : (
            <div className="empty-state">{summary.message}</div>
          )}
        </Panel>
      </section>
    </main>
  );
}

function FlowMap(props: { flows: Flow[]; onSelect: (flowId: string) => void }) {
  const verdicts = ["risky", "allowed", "ambiguous", "unknown", "denied"] as const;
  const counts = verdicts.map((verdict) => ({
    verdict,
    count: props.flows.filter((flow) => flow.verdict === verdict).length
  }));
  const max = Math.max(...counts.map((item) => item.count), 1);
  const paths = props.flows.slice(0, 5);

  return (
    <div className="flow-map-summary">
      <div className="verdict-bars">
        {counts.map((item) => (
          <div className="verdict-bar-row" key={item.verdict}>
            <span className={`verdict verdict-${item.verdict}`}>{item.verdict}</span>
            <div className="bar-track">
              <div className={`bar-fill bar-${item.verdict}`} style={{ width: `${(item.count / max) * 100}%` }} />
            </div>
            <strong>{item.count}</strong>
          </div>
        ))}
      </div>
      <div className="path-list">
        {paths.map((flow) => (
          <button className="path-chip" key={flow.id} onClick={() => props.onSelect(flow.id)} type="button">
            <span>{flow.path.join(" -> ")}</span>
            <span className={`verdict verdict-${flow.verdict}`}>{flow.verdict}</span>
          </button>
        ))}
      </div>
    </div>
  );
}

function FlowDetail(props: { flow: Flow }) {
  return (
    <div className="detail-stack">
      <div>
        <span className={`verdict verdict-${props.flow.verdict}`}>{props.flow.verdict}</span>
        <h3>
          {props.flow.source} to {props.flow.destination}
        </h3>
      </div>
      <dl>
        <div>
          <dt>Service</dt>
          <dd>{formatService(props.flow.service)}</dd>
        </div>
        <div>
          <dt>Path</dt>
          <dd>{props.flow.path.join(" -> ")}</dd>
        </div>
        <div>
          <dt>Matched Rules</dt>
          <dd>
            {props.flow.matched_nat_rules.length} NAT, {props.flow.matched_firewall_rules.length} firewall
          </dd>
        </div>
      </dl>
      <ol className="explanation-steps">
        {props.flow.explanation.map((step) => (
          <li key={`${props.flow.id}-${step.order}`}>
            <strong>{step.title}</strong>
            <span>{step.detail}</span>
            {step.raw_reference ? <code>{step.raw_reference.path}</code> : null}
          </li>
        ))}
      </ol>
      <RuleStory>{flowStory(props.flow)}</RuleStory>
    </div>
  );
}

function FindingDetail(props: { finding: Finding }) {
  return (
    <div className="detail-stack">
      <div>
        <span className={`severity severity-${props.finding.severity}`}>{props.finding.severity}</span>
        <h3>{props.finding.title}</h3>
      </div>
      <p>{props.finding.explanation}</p>
      <dl>
        <div>
          <dt>Confidence</dt>
          <dd>{props.finding.confidence}</dd>
        </div>
        <div>
          <dt>Source Reference</dt>
          <dd>{props.finding.raw_references[0]?.path ?? "Unavailable"}</dd>
        </div>
      </dl>
      <RuleStory>{findingStory(props.finding)}</RuleStory>
    </div>
  );
}

function RuleStory(props: { children: React.ReactNode }) {
  return (
    <section className="rule-story">
      <h4>Rule Story</h4>
      <p>{props.children}</p>
    </section>
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

function SourceButton(props: { active: boolean; children: React.ReactNode; onClick: () => void }) {
  return (
    <button className={`source-tab ${props.active ? "active" : ""}`} onClick={props.onClick} type="button">
      {props.children}
    </button>
  );
}

function Panel(props: { title: string; hint?: string; children: React.ReactNode }) {
  return (
    <section className="panel">
      <div className="panel-heading">
        <h2>{props.title}</h2>
        {props.hint ? <span>{props.hint}</span> : null}
      </div>
      {props.children}
    </section>
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

function postJson<T>(url: string, body: unknown): Promise<T> {
  return fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  }).then(async (response) => {
    if (!response.ok) {
      const payload = (await response.json().catch(() => null)) as { detail?: string } | null;
      throw new Error(payload?.detail ?? `Unexpected status ${response.status}`);
    }
    return response.json() as Promise<T>;
  });
}

function formatService(service: Flow["service"]) {
  const protocol = service.protocol ?? "any";
  const ports = service.ports.length > 0 ? service.ports.join(", ") : "any";
  return `${protocol}/${ports}`;
}

function summaryFromPolicy(policy: Policy, message: string): Summary {
  return {
    config_source: policy.source?.name ?? null,
    interfaces: policy.interfaces.length,
    firewall_rules: policy.firewall_rules.length,
    nat_rules: policy.nat_rules.length,
    flows: policy.flows.length,
    findings: policy.findings.length,
    message
  };
}

function fileFromForm(form: HTMLFormElement, name: string) {
  const input = form.elements.namedItem(name) as HTMLInputElement | null;
  return input?.files?.[0] ?? null;
}

async function optionalFileText(form: HTMLFormElement, name: string) {
  const file = fileFromForm(form, name);
  return file ? file.text() : null;
}

function selectInitialDetail(
  policy: Policy,
  setSelectedFindingId: (value: string | null) => void,
  setSelectedFlowId: (value: string | null) => void,
  setDetailMode: (value: "finding" | "flow") => void
) {
  setSelectedFindingId(policy.findings[0]?.id ?? null);
  setSelectedFlowId(policy.flows[0]?.id ?? null);
  setDetailMode(policy.flows.length > 0 ? "flow" : "finding");
}

function flowStory(flow: Flow) {
  const service = formatService(flow.service);
  if (flow.verdict === "risky") {
    return `Traffic from ${flow.source} can reach ${flow.destination} on ${service}, and the matched policy looks broad or exposed. This is the flow to review first.`;
  }
  if (flow.verdict === "allowed") {
    return `Traffic from ${flow.source} is allowed to ${flow.destination} on ${service}. The listed NAT and firewall steps show which rules make that happen.`;
  }
  if (flow.verdict === "denied") {
    return `Traffic from ${flow.source} to ${flow.destination} on ${service} is blocked by the matched firewall decision.`;
  }
  return `The config hints at traffic from ${flow.source} to ${flow.destination} on ${service}, but there is not enough route or default-policy context to say exactly what happens.`;
}

function findingStory(finding: Finding) {
  if (finding.severity === "critical" || finding.severity === "high") {
    return `This finding points to a rule that may expose important access. Confirm whether the source, destination, and service are intentionally this open.`;
  }
  if (finding.severity === "medium") {
    return `This finding is worth review because the rule may be acceptable only with missing business or network context.`;
  }
  return `This finding is mostly about cleanup or clarity. It may not be dangerous by itself, but it can make future policy review harder.`;
}
