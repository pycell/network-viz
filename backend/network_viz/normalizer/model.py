from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class SourceBackend(StrEnum):
    PFSENSE_XML = "pfsense_xml"
    PFSENSE_API = "pfsense_api"
    IPTABLES = "iptables"


class RuleAction(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REJECT = "reject"
    NAT = "nat"
    DNAT = "dnat"
    SNAT = "snat"
    MASQUERADE = "masquerade"
    UNKNOWN = "unknown"


class NatType(StrEnum):
    DNAT = "dnat"
    SNAT = "snat"
    MASQUERADE = "masquerade"
    REDIRECT = "redirect"
    PORT_FORWARD = "port_forward"


class FlowVerdict(StrEnum):
    ALLOWED = "allowed"
    DENIED = "denied"
    UNKNOWN = "unknown"
    AMBIGUOUS = "ambiguous"
    RISKY = "risky"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RawReference(BaseModel):
    backend: SourceBackend
    path: str
    raw_id: str | None = None
    raw: str | None = None


class ConfigSource(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    backend: SourceBackend
    name: str
    collected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = Field(default_factory=dict)


class Interface(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    name: str
    display_name: str | None = None
    addresses: list[str] = Field(default_factory=list)
    zone: str | None = None
    interface_type: str | None = None
    enabled: bool = True
    raw_reference: RawReference | None = None


class Zone(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    name: str
    subnets: list[str] = Field(default_factory=list)
    trust_level: str | None = None


class Alias(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    name: str
    alias_type: str
    values: list[str] = Field(default_factory=list)
    description: str | None = None
    raw_reference: RawReference | None = None


class Route(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    destination: str
    gateway: str | None = None
    interface: str | None = None
    metric: int | None = None
    raw_reference: RawReference | None = None


class Gateway(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    name: str
    address: str
    interface: str | None = None
    raw_reference: RawReference | None = None


class PortSelector(BaseModel):
    protocol: str | None = None
    ports: list[str] = Field(default_factory=list)


class FirewallRule(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    source: str
    destination: str
    service: PortSelector = Field(default_factory=PortSelector)
    action: RuleAction
    order: int
    interface: str | None = None
    chain: str | None = None
    enabled: bool = True
    log: bool = False
    description: str | None = None
    raw_reference: RawReference | None = None


class NatRule(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    nat_type: NatType
    original_source: str | None = None
    original_destination: str | None = None
    translated_source: str | None = None
    translated_destination: str | None = None
    service: PortSelector = Field(default_factory=PortSelector)
    order: int
    interface: str | None = None
    enabled: bool = True
    description: str | None = None
    raw_reference: RawReference | None = None


class ExplanationStep(BaseModel):
    order: int
    title: str
    detail: str
    raw_reference: RawReference | None = None


class Flow(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    source: str
    destination: str
    service: PortSelector = Field(default_factory=PortSelector)
    verdict: FlowVerdict
    path: list[str] = Field(default_factory=list)
    matched_firewall_rules: list[UUID] = Field(default_factory=list)
    matched_nat_rules: list[UUID] = Field(default_factory=list)
    explanation: list[ExplanationStep] = Field(default_factory=list)


class Finding(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    severity: Severity
    title: str
    explanation: str
    affected_objects: list[UUID] = Field(default_factory=list)
    confidence: Confidence = Confidence.MEDIUM
    raw_references: list[RawReference] = Field(default_factory=list)


class NormalizedConfig(BaseModel):
    source: ConfigSource
    interfaces: list[Interface] = Field(default_factory=list)
    zones: list[Zone] = Field(default_factory=list)
    aliases: list[Alias] = Field(default_factory=list)
    routes: list[Route] = Field(default_factory=list)
    gateways: list[Gateway] = Field(default_factory=list)
    firewall_rules: list[FirewallRule] = Field(default_factory=list)
    nat_rules: list[NatRule] = Field(default_factory=list)
    flows: list[Flow] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
