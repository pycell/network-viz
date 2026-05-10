# Network Policy Visualization and Explanation Engine Plan

## Product Goal

Build a read-only dashboard and explanation engine that helps operators understand complex network policy behavior across pfSense, iptables, NAT, routing, VPNs, and later Kubernetes/WireGuard environments.

The system should answer:

- What are the major traffic flows?
- Which routes, NAT rules, and firewall rules affect each flow?
- Which services are exposed?
- Which rules look risky, broad, shadowed, duplicated, or confusing?
- Why is a flow allowed, denied, translated, routed, or ambiguous?

The first release should focus on visibility and explanation, not policy mutation or automated remediation.

## Guiding Principles

- Read-only first.
- Normalize all backends into a shared policy model.
- Keep raw source references for every normalized object.
- Prefer deterministic offline analysis before live automation.
- Explain findings with evidence, not generic security advice.
- Mark uncertainty explicitly when inventory, routes, aliases, or runtime state are missing.
- Treat XML import and API collection as two ingestion methods for the same pfSense domain model.

## Initial Scope

### In Scope

- pfSense configuration analysis.
- pfSense XML import as the first ingestion method.
- pfSense API collector planned behind the same collector interface.
- iptables and Linux routing analysis.
- NAT, port-forward, pre-routing, post-routing, and forwarding behavior.
- Static dashboard.
- Major flow map.
- Risk finding section.
- Explanation detail section.
- Raw rule/source references.

### Later Scope

- WireGuard analysis.
- Kubernetes NetworkPolicy, CNI rules, and service exposure.
- Cloud firewalls/security groups.
- Historical drift detection.
- Interactive path query: source, destination, protocol, port.
- Remediation suggestions.
- Policy change simulation.

## Architecture

```text
collectors/
  pfsense_xml.py
  pfsense_api.py
  iptables.py
  linux_routes.py

normalizer/
  model.py
  aliases.py
  pfsense.py
  iptables.py

analysis/
  topology.py
  flow_engine.py
  risk_rules.py
  explain.py

api/
  main.py

ui/
  dashboard
```

## Normalized Model

The dashboard and analysis engine should not consume pfSense or iptables objects directly. Collectors convert source-specific configuration into normalized objects.

Core entities:

- `ConfigSource`
- `Interface`
- `Zone`
- `AddressObject`
- `ServiceObject`
- `Alias`
- `Route`
- `Gateway`
- `FirewallRule`
- `NatRule`
- `Flow`
- `Finding`
- `ExplanationStep`
- `RawReference`

Important fields:

- Source backend: `pfsense_xml`, `pfsense_api`, `iptables`.
- Raw object ID/path.
- Rule order.
- Enabled/disabled state.
- Interface or chain.
- Source/destination selectors.
- Protocol and ports.
- Action.
- NAT translation details.
- Logging state.
- Description/comment.
- Confidence level.

## Sprint Plan

### Sprint 0: Project Foundation

Goal: Create the skeleton needed to build safely and iterate quickly.

Deliverables:

- Python project structure.
- FastAPI backend skeleton.
- Pydantic models for normalized network policy objects.
- Basic test setup.
- Sample data directory.
- CLI entry point for local parsing and analysis.
- Static JSON output format for dashboard consumption.

Acceptance criteria:

- `python` command can parse a sample input file and emit normalized JSON.
- Unit tests can run locally.
- Model objects can represent interfaces, firewall rules, NAT rules, routes, and findings.

Open decisions:

- Package manager: `uv`.
- Frontend stack: React/Vite.
- Storage for v1: PostgreSQL.
- Deployment foundation: Dockerfile and Docker Compose.
- Operations foundation: Makefile targets for install, dev, test, lint, format, typecheck, and Docker.

### Sprint 1: pfSense XML Collector

Goal: Parse pfSense `config.xml` and produce normalized objects.

Deliverables:

- XML parser for pfSense config exports.
- Interface extraction.
- Alias extraction.
- Firewall rule extraction.
- NAT/port-forward extraction.
- Gateway and static route extraction where available.
- Raw XML path/reference tracking.
- Fixture-based tests using sanitized sample configs.

Dashboard output:

- Interface list.
- Alias list.
- Firewall rules table.
- NAT/port-forward table.
- Exposed service summary.

Acceptance criteria:

- A pfSense XML export can be loaded without touching a live firewall.
- Rules preserve order, interface, action, enabled state, source, destination, ports, and description.
- NAT rules preserve original destination, translated destination, protocol, and ports.
- Every parsed rule has a raw source reference.

### Sprint 2: pfSense Risk Findings

Goal: Generate useful findings from pfSense configuration alone.

Initial risk rules:

- WAN allow from any source.
- WAN allow to private/internal destination.
- Public port-forward to sensitive ports: `22`, `3389`, `5900`, `5432`, `3306`, `6379`, `9200`, `8080`, `8443`.
- Firewall management ports exposed from WAN or VPN.
- Broad VPN-to-LAN access.
- Any-to-any allow.
- Disabled risky rule retained in config.
- Rule without description/comment.
- Internet-facing allow rule without logging.
- Duplicate rules.
- Basic shadowed rules.
- NAT/port-forward without a corresponding restrictive firewall rule.

Deliverables:

- Risk rule framework.
- Severity model: `critical`, `high`, `medium`, `low`, `info`.
- Finding explanations with affected source references.
- JSON findings output.
- Tests for each initial risk rule.

Acceptance criteria:

- Findings include severity, title, explanation, affected objects, and confidence.
- Findings distinguish confirmed risk from configuration ambiguity.
- Tests cover broad allow, sensitive exposure, duplicate, and shadowed rule cases.

### Sprint 3: Static Dashboard V1

Goal: Present parsed pfSense config, major flows, and findings in a usable read-only dashboard.

Views:

- Overview summary.
- Interfaces/zones.
- Exposed services.
- Firewall rules.
- NAT/port-forwards.
- Risk findings.
- Explanation detail panel.

Layout:

```text
[Source] [Scan Time] [Interfaces] [Firewall Rules] [NAT Rules] [Findings]

[Network Flow Map]

[Major Flows Table]

[Risk Findings]

[Explanation Detail]
```

Deliverables:

- Static dashboard UI.
- Backend endpoint or static JSON loader.
- Flow map visualization.
- Findings table with severity filters.
- Detail panel for selected finding or flow.

Acceptance criteria:

- User can load a sample pfSense config and see interfaces, NAT rules, firewall rules, and findings.
- Risk findings are clickable and show the relevant rule/source reference.
- UI is read-only.

### Sprint 4: Flow Explanation Engine V1

Goal: Explain representative flows through routing, NAT, and firewall policy.

Initial representative flows:

- Internet to each public port-forward.
- Internet to each WAN allow rule.
- LAN to Internet.
- VPN to LAN.
- VPN to DMZ.
- DMZ to LAN.
- Any subnet to firewall management ports.
- Any broad allow rule as a generated flow.

Deliverables:

- Flow generator.
- Basic route decision model.
- NAT transformation model.
- Firewall rule matching model.
- Explanation step output.
- Flow verdicts: `allowed`, `denied`, `unknown`, `ambiguous`, `risky`.

Acceptance criteria:

- Each generated flow includes source, destination, service, matched NAT rules, matched firewall rules, route/interface context, verdict, and explanation.
- The system can explain why a public port-forward appears exposed.
- Ambiguous flows clearly state missing context.

### Sprint 5: iptables Collector

Goal: Add Linux firewall and NAT ingestion.

Inputs:

- `iptables-save`.
- `ip route`.
- `ip rule`.
- Interface/address inventory.

Supported tables/chains:

- `raw`.
- `mangle`.
- `nat`.
- `filter`.
- `PREROUTING`.
- `INPUT`.
- `FORWARD`.
- `OUTPUT`.
- `POSTROUTING`.

Deliverables:

- `iptables-save` parser.
- Chain/rule model.
- NAT rule normalization for DNAT, SNAT, MASQUERADE, REDIRECT.
- Route parser.
- Default policy handling.
- Tests with realistic rule sets.

Acceptance criteria:

- Parser preserves table, chain, order, match criteria, target, comments, and raw rule text.
- DNAT/SNAT/MASQUERADE rules normalize into `NatRule`.
- ACCEPT/DROP/REJECT rules normalize into `FirewallRule`.
- Default chain policy is represented.

### Sprint 5A: Usability and Source Selection Adjustments

Goal: Improve operator workflow before continuing deeper iptables analysis.

Adjustments:

- Use the project favicon in the frontend shell.
- Add source selection for:
  - pfSense XML with manual browser upload.
  - pfSense API with host and credential inputs, kept as an explicit upcoming collector path.
  - iptables local files with manual upload of `iptables-save`, `ip route`, `ip rule`, and `ip addr`.
  - iptables remote SSH with host and credential inputs, kept as an explicit upcoming collector path.
- Re-examine the Major Flow Map and make it communicate actual flow verdict distribution instead of a vague topology cartoon.
- Improve page scrolling discoverability and reduce confusion when panels contain overflow.
- Add a plain-language rule story to the Explanation Detail panel so non-specialists can understand what a selected flow or finding means.

Acceptance criteria:

- User can choose a source type from the dashboard.
- User can upload a pfSense XML file and immediately see normalized policy, findings, flows, and explanations.
- User can upload local iptables command outputs and see normalized rules, NAT, routes, and interfaces.
- Credential-based source modes are visible but clearly marked as not connected until dedicated collectors are implemented.
- Explanation Detail includes a simple human-readable summary below technical steps.
- Major Flow Map either conveys useful aggregate flow information or is flagged for removal in a later design pass.

### Sprint 5B: iptables SSH Collection

Goal: Collect Linux firewall data from remote VPS hosts over SSH and feed it into the existing iptables parser.

Approach:

- Use the local OpenSSH client so collection follows the operator's existing Mac terminal setup.
- Prefer SSH keys, ssh-agent, and `~/.ssh/config`; do not store credentials in the app.
- Run the same remote commands documented in the local upload flow:
  - `iptables-save`
  - `ip route`
  - `ip rule`
  - `ip -o -4 addr show`
- Parse collected stdout with the Sprint 5 iptables parser.
- Return actionable errors when SSH, sudo, or remote commands fail.

Acceptance criteria:

- User can enter a host, username, and optional port in the iptables SSH source mode.
- Backend connects over SSH and returns normalized firewall rules, NAT rules, routes, interfaces, and policy-routing metadata.
- Failed SSH collection returns a clear HTTP error instead of `501 Not Implemented`.
- Tests cover command execution, parse integration, and API error handling without requiring a live VPS.

### Sprint 6: iptables Risk and Explanation

Goal: Analyze Linux firewall behavior and explain common forwarding/NAT paths.

Initial risk rules:

- Default `ACCEPT` on `INPUT`.
- Default `ACCEPT` on `FORWARD`.
- Broad `ACCEPT` before restrictive rules.
- Public DNAT to private sensitive service.
- MASQUERADE/SNAT hiding cross-zone access.
- PREROUTING DNAT without matching FORWARD restriction.
- Duplicate rules.
- Shadowed rules.
- Docker/Kubernetes chains that bypass expected policy.
- Open forwarding between private zones.

Deliverables:

- iptables risk rules.
- Chain traversal explanation.
- NAT plus filter explanation.
- Findings integration into dashboard.

Acceptance criteria:

- Dashboard can show pfSense and iptables findings using the same UI.
- Explanation can show table/chain traversal for representative flows.
- NAT and forwarding behavior are visible in flow detail.

### Sprint 7: pfSense API Collector

Goal: Add live pfSense collection without changing the analysis engine.

Approach:

- Keep API read-only.
- Implement behind the same `ConfigCollector` interface as XML.
- Normalize API responses into the same pfSense intermediate model.
- Store API collection metadata separately from policy objects.

Deliverables:

- pfSense API client.
- Authentication configuration.
- Read-only collection for interfaces, aliases, firewall rules, NAT rules, gateways, and routes where available.
- API capability/version detection.
- Error handling for missing API package or unsupported endpoints.
- Tests using recorded/synthetic API responses.

Acceptance criteria:

- API collector produces the same normalized output shape as XML collector.
- Dashboard does not care whether pfSense data came from XML or API.
- Failed or partial API collection produces actionable error messages.

Security requirements:

- Dedicated pfSense read-only user.
- API access restricted to dashboard host IP.
- TLS verification enabled by default.
- Secrets loaded from environment or secret store.
- No policy mutation endpoints in v1.

### Sprint 8: History and Drift Detection

Goal: Track how policy changes over time.

Deliverables:

- Scan persistence.
- Config source history.
- Diff between scans.
- New/removed/changed rule detection.
- New exposure detection.
- Changed route/NAT detection.

Acceptance criteria:

- User can compare two scans.
- Dashboard highlights newly exposed services.
- Dashboard highlights new broad allow rules.
- Drift report can be exported.

### Sprint 9: WireGuard and VPN Expansion

Goal: Model VPN access paths more accurately.

Deliverables:

- WireGuard config parser.
- Peer and allowed IP extraction.
- Tunnel interface mapping.
- VPN-to-zone flow generation.
- VPN risk rules.

Risk rules:

- Peer allowed IPs too broad.
- VPN peer can access all LANs.
- Overlapping allowed IPs.
- Missing peer description/owner metadata.
- VPN path bypasses expected firewall zone.

Acceptance criteria:

- Dashboard shows peers, allowed IPs, and reachable zones.
- Flow engine can explain VPN-to-internal paths.

### Sprint 10: Kubernetes Expansion

Goal: Add Kubernetes policy and service exposure to the same graph.

Deliverables:

- Kubernetes resource collector.
- NetworkPolicy parser.
- Service/Ingress exposure model.
- Node subnet and pod CIDR modeling.
- CNI-specific extension points.

Risk rules:

- Namespace without default deny.
- Public LoadBalancer/Ingress to sensitive service.
- Broad egress.
- Broad namespace-to-namespace access.
- HostNetwork workloads.
- NodePort exposure.

Acceptance criteria:

- Kubernetes objects appear as zones/services in the dashboard.
- Flow engine can show external-to-service and pod-to-network paths.

## MVP Definition

The MVP is complete when:

- A user can upload a pfSense XML export.
- The dashboard shows interfaces, aliases, firewall rules, NAT rules, exposed services, and risk findings.
- The engine generates representative flows.
- Each flow has an explanation.
- Findings include references to the originating rule/config object.
- The architecture can add iptables and pfSense API without rewriting the UI.

## Data Collection Strategy

### pfSense XML

Use first because it is:

- Offline.
- Deterministic.
- Low-risk for production firewalls.
- Easy to sanitize and test.
- Useful for historical review.

### pfSense API

Add after XML because it is:

- Better for scheduled scans.
- Better for drift detection.
- Useful for inventory refresh.
- More operationally sensitive.
- Dependent on API availability, permissions, and installed packages.

### iptables

Collect command outputs rather than requiring root-level live integration at first:

- `iptables-save`.
- `ip route`.
- `ip rule`.
- `ip addr`.

This allows offline analysis and safer testing.

## Dashboard V1 Information Design

Top summary:

- Config source.
- Last scan time.
- Interface count.
- Firewall rule count.
- NAT rule count.
- Finding count.
- Public exposure count.

Main sections:

- Major flow map.
- Exposed services.
- Risk findings.
- Rules and NAT tables.
- Explanation detail.

Finding detail should show:

- Severity.
- Why it matters.
- Affected rules.
- Matched source/destination/service.
- Confidence.
- Suggested next investigation step.
- Raw source reference.

Flow detail should show:

- Source zone/subnet.
- Destination zone/subnet/service.
- Ingress interface.
- NAT transformation.
- Route decision.
- Matched firewall rule.
- Final verdict.
- Ambiguities.

## Testing Strategy

Test levels:

- Unit tests for parsers.
- Unit tests for normalizers.
- Unit tests for risk rules.
- Golden JSON tests for sample configs.
- Flow explanation snapshot tests.
- UI smoke tests.

Required fixtures:

- Minimal pfSense config.
- pfSense with aliases.
- pfSense with WAN port-forwards.
- pfSense with broad VPN access.
- pfSense with floating rules.
- iptables with DNAT and FORWARD.
- iptables with default ACCEPT.
- iptables with Docker-style chains.

## Important Open Questions

1. Should the first implementation use `uv`, `poetry`, or plain `pip`?
2. Do we want the first dashboard as React/Vite, or a simpler server-rendered/static UI?
3. Should v1 store scans, or should it be stateless and operate from uploaded files only?
4. Do you have sanitized pfSense XML exports we can use as fixtures?
5. Do you have representative `iptables-save`, `ip route`, `ip rule`, and `ip addr` outputs?
6. Which environment matters first: home lab, enterprise edge firewall, production data center, cloud VM gateway, or Kubernetes nodes?
7. Which pfSense version do you use: CE or Plus, and which version number?
8. Are you willing to install a pfSense API package later, or should API support be optional only?
9. Should findings be opinionated security checks, operational debugging checks, or both?
10. Should the dashboard eventually support multiple sites/firewalls in one view?

## Suggested Immediate Next Steps

1. Choose project tooling.
2. Add normalized model definitions.
3. Add pfSense XML parser.
4. Add sanitized sample fixtures.
5. Add first risk rules.
6. Build static dashboard against generated JSON.
