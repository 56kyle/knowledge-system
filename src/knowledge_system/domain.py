"""Validated value models for the knowledge_system package."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from datetime import datetime
from datetime import timezone
from enum import Enum
from typing import TYPE_CHECKING
from typing import ClassVar
from typing import Literal
from typing import cast

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field
from pydantic import field_validator
from pydantic import model_validator

from knowledge_system.constants import DEFAULT_PYDANTIC_CONFIG
from knowledge_system.constants import SCHEMA_VERSION
from knowledge_system.immutable import deep_freeze


Slug = str
Digest = str

if TYPE_CHECKING:
    from knowledge_system.authentication import AuthenticatedPrincipal


def _aware_utc(value: datetime) -> datetime:
    """Reject naive datetimes and normalize aware values to UTC."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime must be timezone-aware")
    return value.astimezone(timezone.utc)


class FrozenModel(BaseModel):
    """Base for immutable boundary values with closed schemas."""

    model_config: ClassVar[ConfigDict] = DEFAULT_PYDANTIC_CONFIG

    @model_validator(mode="after")
    def nested_values_are_immutable(self) -> FrozenModel:
        """Deep-freeze every nested container after boundary validation."""
        for name in type(self).model_fields:
            value = cast("object", getattr(self, name))
            object.__setattr__(self, name, deep_freeze(value))
        return self


class Severity(str, Enum):
    """Validation finding severity."""

    ADVISORY = "advisory"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class Finding(FrozenModel):
    """One deterministic and machine-readable diagnostic."""

    severity: Severity
    code: str
    message: str
    path: str | None = None
    line: int | None = Field(default=None, ge=1)
    details: Mapping[str, str | int | bool | tuple[str, ...]] = Field(default_factory=dict)


class NoteDiscovery(FrozenModel):
    """Collection note discovery rules."""

    roots: tuple[str, ...] = (".",)
    include: tuple[str, ...] = ("*.md", "**/*.md")
    exclude: tuple[str, ...] = ()
    adapter: Literal["portable", "obsidian"] = "portable"


class InboxLimits(FrozenModel):
    """Bounds for agent-created inbox material."""

    files: int = Field(default=500, ge=0)
    bytes: int = Field(default=10_000_000, ge=0)


class AgentPolicy(FrozenModel):
    """Declared local mutation policy."""

    direct: tuple[str, ...] = (
        "register",
        "create",
        "set_field",
        "remove_field",
        "replace_subtree",
        "move",
        "reserve_collection",
        "retire_identity",
    )
    review_required: tuple[str, ...] = ()
    explicit_authorization: tuple[str, ...] = ()
    concurrency: Literal["compare-and-swap"] = "compare-and-swap"
    inbox_limits: InboxLimits = Field(default_factory=InboxLimits)


class RelationPolicy(FrozenModel):
    """Relation vocabulary and default resolution behavior."""

    vocabulary: str = "core@1"
    default_resolution: Literal["required", "prospective"] = "required"
    prospective_predicates: tuple[str, ...] = ()


class ProfileSelection(FrozenModel):
    """Enabled profile versions and collection-specific settings."""

    enabled: Mapping[str, int] = Field(default_factory=dict)
    settings: Mapping[str, Mapping[str, object]] = Field(default_factory=dict)


class OptionalReferences(FrozenModel):
    """References to owner-controlled policy and derived recipes."""

    catalog: str | None = None
    trust_policy: str | None = None
    trust_policy_id: str | None = None
    projection_recipe: str | None = None
    source_registry: str | None = None
    source_version_registry: str | None = None
    capture_registry: str | None = None
    asset_registry: str | None = None


class CollectionIdentity(FrozenModel):
    """Stable identity and trust placement of a collection."""

    id: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    title: str
    mode: Literal["canonical", "inbox", "derived"] = "canonical"
    trust_domain: str = Field(pattern=r"^[a-z0-9]+(?:[.-][a-z0-9]+)*$")


class CollectionManifest(FrozenModel):
    """Versioned collection contract loaded from collection.yaml."""

    version: Literal[1] = SCHEMA_VERSION
    collection: CollectionIdentity
    notes: NoteDiscovery = Field(default_factory=NoteDiscovery)
    profiles: ProfileSelection = Field(default_factory=ProfileSelection)
    relations: RelationPolicy = Field(default_factory=RelationPolicy)
    agents: AgentPolicy = Field(default_factory=AgentPolicy)
    references: OptionalReferences = Field(default_factory=OptionalReferences)


class ProfileLock(FrozenModel):
    """Integrity binding for a profile or vocabulary."""

    identifier: str
    version: int = Field(ge=1)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    path: str | None = None


class ProfileLockFile(FrozenModel):
    """Collection profile lock file."""

    version: Literal[1] = SCHEMA_VERSION
    profiles: tuple[ProfileLock, ...] = ()
    relation_vocabularies: tuple[ProfileLock, ...] = ()


class RetirementRecord(FrozenModel):
    """Append-only disposition for one identity that can never be reused."""

    id: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    disposition: str = Field(min_length=1)
    retired_on: date
    successor: str | None = None


class RetiredIdentityFile(FrozenModel):
    """Append-only record of identities that cannot be reused."""

    version: Literal[1] = SCHEMA_VERSION
    records: tuple[RetirementRecord, ...] = ()

    @model_validator(mode="after")
    def identities_are_unique(self) -> RetiredIdentityFile:
        """Reject ambiguous dispositions for the same retired identity."""
        identities = [record.id for record in self.records]
        if len(identities) != len(set(identities)):
            raise ValueError("retirement ledger identities must be unique")
        return self


class Origin(str, Enum):
    """How durable note material entered the collection."""

    HUMAN = "human"
    AGENT = "agent"
    MIXED = "mixed"
    IMPORTED = "imported"


class ReviewStatus(str, Enum):
    """Trust status scoped to the current note revision."""

    UNREVIEWED = "unreviewed"
    REVIEWED = "reviewed"
    REVIEW_REQUIRED = "review_required"


class EpistemicStatus(str, Enum):
    """Claim-level epistemic posture."""

    OBSERVATION = "observation"
    HYPOTHESIS = "hypothesis"
    SUPPORTED = "supported"
    CONTESTED = "contested"
    REFUTED = "refuted"
    MIXED = "mixed"


class RecordStatus(str, Enum):
    """Durable record lifecycle independent of FLAP."""

    ACTIVE = "active"
    SUPERSEDED = "superseded"
    RETIRED = "retired"


class RelationResolution(str, Enum):
    """Whether a relation target must already resolve."""

    REQUIRED = "required"
    PROSPECTIVE = "prospective"


class RelationConfidence(str, Enum):
    """Whether an edge is authored or derived."""

    ASSERTED = "asserted"
    INFERRED = "inferred"


class Relation(FrozenModel):
    """Typed edge retained in canonical Markdown."""

    predicate: str = Field(pattern=r"^[a-z][a-z0-9_-]*$")
    target: str
    resolution: RelationResolution | None = None
    confidence: RelationConfidence = RelationConfidence.ASSERTED

    @model_validator(mode="before")
    @classmethod
    def parse_scalar_grammar(cls, value: object) -> object:
        """Parse the portable scalar relation grammar when supplied."""
        if not isinstance(value, str):
            return value
        segments = [segment.strip() for segment in value.split(";")]
        predicate, separator, target = segments[0].partition(" ")
        if not predicate or not separator or not target:
            raise ValueError("relation must start with '<predicate> <target>'")
        parsed: dict[str, object] = {"predicate": predicate, "target": target}
        for option in segments[1:]:
            key, equals, option_value = option.partition("=")
            if equals != "=" or key not in {"resolution", "confidence"} or not option_value:
                raise ValueError(f"invalid relation option: {option}")
            if key in parsed:
                raise ValueError(f"duplicate relation option: {key}")
            parsed[key] = option_value
        return parsed

    @model_validator(mode="after")
    def canonical_edges_are_asserted(self) -> Relation:
        """Reject derived confidence in canonical note envelopes."""
        if self.confidence is RelationConfidence.INFERRED:
            raise ValueError("canonical note relations must be asserted")
        return self


class SourceLocator(FrozenModel):
    """Exact source position or quote selector."""

    source: str
    kind: Literal["page", "heading", "timestamp", "quote", "line", "uri-fragment"]
    value: str
    end: str | None = None
    exact_quote: str | None = None
    prefix: str | None = None
    suffix: str | None = None

    @field_validator("source")
    @classmethod
    def source_is_versioned(cls, value: str) -> str:
        """Require locators to address an immutable source version."""
        if not value.startswith("source-version:"):
            raise ValueError("locator source must use a source-version: reference")
        return value


class SourceRecord(FrozenModel):
    """Logical external or local source identity."""

    id: str
    title: str
    uri: str | None = None
    creators: tuple[str, ...] = ()


class SourceVersion(FrozenModel):
    """Immutable observed version of a source."""

    id: str
    source: str
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    observed_at: datetime
    locator: str | None = None

    @field_validator("observed_at")
    @classmethod
    def observed_at_is_aware_utc(cls, value: datetime) -> datetime:
        """Normalize an aware source observation time to UTC."""
        return _aware_utc(value)

    @field_validator("source")
    @classmethod
    def source_is_canonical(cls, value: str) -> str:
        """Require the immutable version to identify its logical source."""
        if not value.startswith("source:"):
            raise ValueError("source versions must use a source: reference")
        return value


class CaptureRecord(FrozenModel):
    """Immutable capture linked to an exact source version when applicable."""

    id: str
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    captured_at: datetime
    captured_by: str
    source_version: str | None = None
    locator: SourceLocator | None = None

    @field_validator("captured_at")
    @classmethod
    def captured_at_is_aware_utc(cls, value: datetime) -> datetime:
        """Normalize an aware capture time to UTC."""
        return _aware_utc(value)

    @field_validator("source_version")
    @classmethod
    def source_version_is_canonical(cls, value: str | None) -> str | None:
        """Require captures to bind exact source versions when supplied."""
        if value is not None and not value.startswith("source-version:"):
            raise ValueError("capture source_version must use a source-version: reference")
        return value

    @model_validator(mode="after")
    def locator_matches_capture_source(self) -> CaptureRecord:
        """Keep the capture and its exact locator on the same source version."""
        if self.locator is not None and self.source_version != self.locator.source:
            raise ValueError("capture locator source must match capture source_version")
        return self


class AssetRecord(FrozenModel):
    """Referenced binary asset stored outside note directories."""

    id: str
    uri: str
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    media_type: str | None = None
    cached_path: str | None = None
    snapshot: str | None = None

    @field_validator("snapshot")
    @classmethod
    def snapshot_is_canonical(cls, value: str | None) -> str | None:
        """Require asset snapshots to use immutable asset references."""
        if value is not None and not value.startswith("asset:"):
            raise ValueError("asset snapshot must use an asset: reference")
        return value


class RegistryEntry(FrozenModel):
    """Verification state for one manifest-declared provenance record."""

    reference: str
    status: Literal["verified", "unverifiable", "missing", "unavailable", "integrity_mismatch"]
    expected_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    observed_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def integrity_state_matches_hashes(self) -> RegistryEntry:
        """Keep declared verification state consistent with available hashes."""
        if self.status == "verified" and (
            self.expected_sha256 is not None
            and self.observed_sha256 is not None
            and self.expected_sha256 != self.observed_sha256
        ):
            raise ValueError("verified registry entry hashes must match")
        if self.status == "integrity_mismatch" and (
            self.expected_sha256 is None or self.observed_sha256 is None or self.expected_sha256 == self.observed_sha256
        ):
            raise ValueError("integrity mismatch requires distinct expected and observed hashes")
        return self


class ProvenanceRegistry(FrozenModel):
    """Contained versioned registry of canonical provenance identities."""

    version: Literal[1] = SCHEMA_VERSION
    entries: tuple[RegistryEntry, ...] = ()

    @model_validator(mode="after")
    def references_are_unique(self) -> ProvenanceRegistry:
        """Reject ambiguous verification state for one identity."""
        references = [entry.reference for entry in self.entries]
        if len(references) != len(set(references)):
            raise ValueError("registry references must be unique")
        return self


class ReviewAttestation(FrozenModel):
    """Human review attestation for one content digest."""

    status: ReviewStatus
    reviewed_by: str | None = None
    reviewed_at: datetime | None = None
    basis: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")

    @field_validator("reviewed_at")
    @classmethod
    def reviewed_at_is_aware_utc(cls, value: datetime | None) -> datetime | None:
        """Normalize an optional aware review time to UTC."""
        return _aware_utc(value) if value is not None else None

    @model_validator(mode="after")
    def require_complete_review(self) -> ReviewAttestation:
        """Require complete review evidence only for reviewed revisions."""
        values = (self.reviewed_by, self.reviewed_at, self.basis)
        if self.status is ReviewStatus.REVIEWED and any(value is None for value in values):
            raise ValueError("reviewed status requires reviewer, timestamp, and basis")
        if self.status is not ReviewStatus.REVIEWED and any(value is not None for value in values):
            raise ValueError("review evidence is only valid for reviewed status")
        return self


class LiteratureItem(FrozenModel):
    """One Literature processing queue item."""

    text: str
    checked: bool = False
    outcome: Literal["atomic", "project", "discarded", "duplicate", "deferred"] | None = None
    review_due: str | None = None
    review_event: str | None = None

    @model_validator(mode="after")
    def deferral_remains_unresolved(self) -> LiteratureItem:
        """Require deferred work to stay unchecked with a review trigger."""
        if self.outcome == "deferred" and (self.checked or (self.review_due is None and self.review_event is None)):
            raise ValueError("deferred Literature must be unchecked and have a review trigger")
        terminal = {"atomic", "project", "discarded", "duplicate"}
        if self.checked != (self.outcome in terminal):
            raise ValueError("Literature checked state must match a terminal outcome")
        return self


class ProjectTask(FrozenModel):
    """One actionable Project task."""

    text: str
    checked: bool = False
    action: str | None = None


class NoteEnvelope(FrozenModel):
    """Progressive metadata envelope for a registered Markdown note."""

    id: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    profiles: tuple[str, ...] = ()
    created_by: str
    contributors: tuple[str, ...] = ()
    origin: Origin = Origin.HUMAN
    review: ReviewAttestation = Field(default_factory=lambda: ReviewAttestation(status=ReviewStatus.UNREVIEWED))
    epistemic_status: EpistemicStatus | None = None
    record_status: RecordStatus = RecordStatus.ACTIVE
    tags: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()
    relations: tuple[Relation, ...] = ()
    sources: tuple[str, ...] = ()
    captures: tuple[str, ...] = ()
    assets: tuple[str, ...] = ()
    up: str | None = None
    flap_type: Literal["fleeting", "literature", "atomic", "project"] | None = None
    processing_state: Literal["unfiled", "processed", "deferred"] | None = None
    review_due: str | None = None
    source_version: str | None = None
    literature_items: tuple[LiteratureItem, ...] = ()
    project_state: str | None = None
    outcome: str | None = None
    tasks: tuple[ProjectTask, ...] = ()
    research_kind: str | None = None
    research_depth: Literal["named", "scanned", "studied", "applied"] | None = None
    led_to: tuple[str, ...] = ()
    research_role: Literal["note", "map", "frontier"] | None = None

    @field_validator("profiles")
    @classmethod
    def profile_references_are_versioned(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        """Require explicit profile versions."""
        for value in values:
            name, separator, version = value.partition("@")
            if not name or separator != "@" or not version.isdigit():
                raise ValueError(f"invalid profile reference: {value}")
        return values


class CollectionNote(FrozenModel):
    """Parsed Markdown note and its collection-relative identity."""

    path: str
    title: str
    envelope: NoteEnvelope | None = None
    body: str
    content_sha256: str
    headings: tuple[str, ...] = ()
    block_ids: tuple[str, ...] = ()
    links: tuple[str, ...] = ()
    properties: Mapping[str, object] = Field(default_factory=dict)


class DeclarativeField(FrozenModel):
    """Custom-profile field contract."""

    name: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    type: Literal["string", "integer", "boolean", "string-list"]
    required: bool = False
    enum: tuple[str, ...] = ()


class DeclarativeInvariant(FrozenModel):
    """Supported non-executable custom-profile invariant."""

    kind: Literal["required_together", "exactly_one", "requires"]
    fields: tuple[str, ...] = Field(min_length=1)


class PredicateDefinition(FrozenModel):
    """Locked canonical relation predicate behavior."""

    name: str = Field(pattern=r"^[a-z][a-z0-9_-]*$")
    default_resolution: RelationResolution | None = None
    prospective_allowed: bool = False

    @model_validator(mode="before")
    @classmethod
    def expand_scalar_name(cls, value: object) -> object:
        """Keep the concise scalar form when a predicate has no override."""
        return {"name": value} if isinstance(value, str) else value


class ProfileDefinition(FrozenModel):
    """Versioned declarative extension profile."""

    version: Literal[1] = SCHEMA_VERSION
    id: str
    field_prefix: str = Field(pattern=r"^[a-z][a-z0-9_]*_$")
    fields: tuple[DeclarativeField, ...]
    invariants: tuple[DeclarativeInvariant, ...] = ()
    predicates: tuple[PredicateDefinition, ...] = ()

    @model_validator(mode="after")
    def fields_are_uniquely_owned(self) -> ProfileDefinition:
        """Reject duplicate field ownership inside one profile."""
        names = [field.name for field in self.fields]
        if len(names) != len(set(names)):
            raise ValueError("profile field names must be unique")
        known = set(names)
        reserved = set(NoteEnvelope.model_fields)
        if any(name in reserved or not name.startswith(self.field_prefix) for name in names):
            raise ValueError("custom fields must use their declared prefix and not own reserved fields")
        predicates = [predicate.name for predicate in self.predicates]
        if len(predicates) != len(set(predicates)):
            raise ValueError("profile predicates must be unique")
        if any(not set(invariant.fields).issubset(known) for invariant in self.invariants):
            raise ValueError("invariant names a field the profile does not own")
        if any(invariant.kind == "requires" and len(invariant.fields) < 2 for invariant in self.invariants):
            raise ValueError("requires invariants need an ordered source and at least one dependency")
        signatures = [(invariant.kind, invariant.fields) for invariant in self.invariants]
        if len(signatures) != len(set(signatures)):
            raise ValueError("profile invariants must be unique")
        return self


class InspectionReport(FrozenModel):
    """Read-only collection snapshot and diagnostics."""

    schema_version: Literal[1] = SCHEMA_VERSION
    collection_root: str
    manifest: CollectionManifest | None = None
    notes: tuple[CollectionNote, ...] = ()
    findings: tuple[Finding, ...] = ()


class ValidationReport(FrozenModel):
    """Collection validation results."""

    schema_version: Literal[1] = SCHEMA_VERSION
    collection_root: str
    findings: tuple[Finding, ...] = ()

    @property
    def has_blocking_findings(self) -> bool:
        """Return whether error or critical findings prevent acceptance."""
        return any(f.severity in {Severity.ERROR, Severity.CRITICAL} for f in self.findings)


class InspectRequest(FrozenModel):
    """Inputs for collection inspection."""

    collection: str
    manifest: str | None = None
    catalog: str | None = None
    repo_roots: Mapping[str, str] = Field(default_factory=dict)


class ValidateRequest(InspectRequest):
    """Inputs for collection validation."""

    external_policy: TrustPolicy | None = None
    expected_policy_id: str | None = None
    expected_policy_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class CanonicalReference(FrozenModel):
    """Parsed durable reference."""

    scheme: Literal["note", "source", "source-version", "capture", "asset", "workflow"]
    collection: str | None = None
    identifier: str
    block: str | None = None


class CatalogEntry(FrozenModel):
    """Deployment locator for one collection identity."""

    collection_id: str
    manifest: str
    repo_root: str | None = None
    trust_domains: frozenset[str]


class CollectionCatalog(FrozenModel):
    """Owner-maintained collection locator catalog."""

    version: Literal[1] = SCHEMA_VERSION
    collections: tuple[CatalogEntry, ...]

    @model_validator(mode="after")
    def collection_ids_are_unique(self) -> CollectionCatalog:
        """Reject deployment ambiguity at the catalog boundary."""
        identifiers = [entry.collection_id for entry in self.collections]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("catalog collection IDs must be unique")
        return self


class ResolutionContext(FrozenModel):
    """Authorized resolution inputs."""

    catalog: CollectionCatalog
    catalog_root: str
    repo_roots: Mapping[str, str] = Field(default_factory=dict)
    allowed_collections: tuple[str, ...] = ()
    allowed_file_roots: tuple[str, ...] = ()


class ResolutionResult(FrozenModel):
    """Resolved reference without exposing unauthorized targets."""

    reference: CanonicalReference
    path: str
    line: int | None = None
    effective_domains: frozenset[str] = frozenset()
    revision_attestation_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class CrossDomainRule(FrozenModel):
    """Explicitly allowed relation across trust domains."""

    source_domains: frozenset[str]
    destination_domains: frozenset[str]
    predicates: frozenset[str]


class TrustPolicy(FrozenModel):
    """Owner-controlled trust-domain relation policy."""

    version: Literal[1] = SCHEMA_VERSION
    id: str
    rules: tuple[CrossDomainRule, ...] = ()


class TrustGrant(FrozenModel):
    """Time-bounded operation authorization for an authenticated principal."""

    principal: str
    task: str
    actions: frozenset[str]
    domains: frozenset[str]
    collections: frozenset[str] = frozenset()
    expires_at: datetime

    @field_validator("expires_at")
    @classmethod
    def expires_at_is_aware_utc(cls, value: datetime) -> datetime:
        """Normalize an aware grant expiry to UTC."""
        return _aware_utc(value)


class TrustDomainDefinition(FrozenModel):
    """One owner-defined trust domain."""

    id: str = Field(pattern=r"^[a-z0-9]+(?:[.-][a-z0-9]+)*$")


class TrustEnclaveDefinition(FrozenModel):
    """One exact trust-domain set and its optional deployment handles."""

    id: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    domains: frozenset[str] = Field(min_length=1)
    index_handle: str | None = None
    credential_handle: str | None = None


class TrustDomainRegistry(FrozenModel):
    """Owner-maintained trust domains and exact-domain enclaves."""

    version: Literal[1] = SCHEMA_VERSION
    domains: tuple[TrustDomainDefinition, ...]
    enclaves: tuple[TrustEnclaveDefinition, ...]


ControlAction = Literal[
    "administer",
    "read",
    "link",
    "retrieve",
    "synthesize",
    "declassify",
    "update_local_evidence",
    "register",
    "create",
    "set_field",
    "remove_field",
    "replace_subtree",
    "move",
    "reserve_collection",
    "retire_identity",
]


class OwnerGrant(FrozenModel):
    """Permanent authority held only by the control repository owner."""

    principal: str
    task: Literal["*"] = "*"
    actions: frozenset[ControlAction] = Field(min_length=1)
    domains: frozenset[str] = Field(min_length=1)
    collections: frozenset[str] = frozenset()
    expires_at: None = None


class TaskScopedGrant(FrozenModel):
    """Time-bounded authority for one explicit task and collection set."""

    principal: str
    task: str = Field(min_length=1)
    actions: frozenset[ControlAction] = Field(min_length=1)
    domains: frozenset[str] = Field(min_length=1)
    collections: frozenset[str] = Field(min_length=1)
    expires_at: datetime

    @field_validator("task")
    @classmethod
    def task_is_bounded(cls, value: str) -> str:
        """Require one non-wildcard canonical task string."""
        if not value or value != value.strip() or value == "*":
            raise ValueError("task-scoped grant task must be nonempty, trimmed, and not '*'")
        return value

    @field_validator("expires_at")
    @classmethod
    def expires_at_is_aware_utc(cls, value: datetime) -> datetime:
        """Normalize an aware grant expiry to UTC."""
        return _aware_utc(value)


class GrantRegistry(FrozenModel):
    """Owner and task-scoped authorization grants."""

    version: Literal[1] = SCHEMA_VERSION
    grants: tuple[OwnerGrant | TaskScopedGrant, ...]


class SemanticRelease(FrozenModel):
    """Accepted digest for one authoritative semantic release."""

    identifier: str
    version: int = Field(ge=1)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class SemanticReleaseRegistry(FrozenModel):
    """Accepted profile and relation-vocabulary releases."""

    version: Literal[1] = SCHEMA_VERSION
    profiles: tuple[SemanticRelease, ...] = ()
    relation_vocabularies: tuple[SemanticRelease, ...] = ()


class KnowledgeEdge(FrozenModel):
    """Resolved relation used for trust and impact analysis."""

    source: str
    target: str
    predicate: str


class KnowledgeSnapshot(FrozenModel):
    """Minimal graph snapshot for domain propagation."""

    node_domains: Mapping[str, frozenset[str]]
    edges: tuple[KnowledgeEdge, ...] = ()


class DomainAnalysis(FrozenModel):
    """Fixed-point effective trust domains for graph nodes."""

    effective_domains: Mapping[str, frozenset[str]]


class FilePrecondition(FrozenModel):
    """Expected state of one mutation target."""

    path: str
    exists: bool
    sha256: str | None = None


class PlannedFile(FrozenModel):
    """Complete proposed bytes for one file and its readable diff."""

    path: str
    before_sha256: str | None = None
    after_sha256: str | None
    content_base64: str | None
    diff: str
    delete: bool = False


class IdentityReservation(FrozenModel):
    """Expected identity availability bound to one namespace and collection."""

    namespace: Literal["note", "collection"]
    collection_id: str
    identifier: str
    expected_available: bool = True


class MutationIntent(str, Enum):
    """Supported local mutation operations."""

    REGISTER = "register"
    CREATE = "create"
    SET_FIELD = "set_field"
    REMOVE_FIELD = "remove_field"
    REPLACE_SUBTREE = "replace_subtree"
    MOVE = "move"
    RESERVE_COLLECTION = "reserve_collection"
    RETIRE_IDENTITY = "retire_identity"


class RegisterMutationPayload(FrozenModel):
    """Explicit registration fields for the generic mutation boundary."""

    origin: Origin
    profiles: tuple[str, ...] = ()


class RetirementPayload(FrozenModel):
    """Required durable disposition for retiring one active identity."""

    disposition: str = Field(min_length=1)
    retired_on: date
    successor: str | None = None


class MutationRequest(FrozenModel):
    """Validated request for a supported semantic mutation."""

    intent: MutationIntent
    collection: str
    actor: str
    task: str
    path: str | None = None
    destination: str | None = None
    field: str | None = None
    value: RegisterMutationPayload | RetirementPayload | CatalogEntry | tuple[str, ...] | str | None = None
    expected_git_revision: str | None = None
    trust_policy: TrustPolicy | None = None
    trust_grant: TrustGrant | None = None
    expected_policy_id: str | None = None
    expected_policy_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="before")
    @classmethod
    def payload_has_exact_raw_shape(cls, value: object) -> object:
        """Reject coercible payload types before union parsing can alter them."""
        if isinstance(value, cls):
            return value
        if not isinstance(value, Mapping):
            raise ValueError("mutation request must be a mapping")
        raw = cast("Mapping[object, object]", value)
        raw_intent = raw.get("intent")
        if not isinstance(raw_intent, (str, MutationIntent)):
            raise ValueError("mutation intent must be a string")
        try:
            intent = MutationIntent(raw_intent)
        except ValueError as error:
            raise ValueError("mutation intent is unsupported") from error
        payload = raw.get("value")
        valid = _raw_mutation_payload_matches(intent, payload)
        if not valid:
            raise ValueError(f"{intent.value} has an incompatible raw payload")
        return raw

    @model_validator(mode="after")
    def payload_matches_intent(self) -> MutationRequest:
        """Reject requests whose payload shape cannot serve their intent."""
        expected: dict[MutationIntent, type[object] | tuple[type[object], ...]] = {
            MutationIntent.REGISTER: RegisterMutationPayload,
            MutationIntent.CREATE: str,
            MutationIntent.SET_FIELD: tuple,
            MutationIntent.REMOVE_FIELD: type(None),
            MutationIntent.REPLACE_SUBTREE: tuple,
            MutationIntent.MOVE: type(None),
            MutationIntent.RESERVE_COLLECTION: CatalogEntry,
            MutationIntent.RETIRE_IDENTITY: RetirementPayload,
        }
        if not isinstance(self.value, expected[self.intent]):
            raise ValueError(f"{self.intent.value} has an incompatible payload")
        return self


def _raw_mutation_payload_matches(intent: MutationIntent, payload: object) -> bool:
    """Check the uncoerced payload carrier required by one mutation intent."""
    if intent is MutationIntent.CREATE:
        return type(payload) is str
    if intent in {MutationIntent.SET_FIELD, MutationIntent.REPLACE_SUBTREE}:
        return _is_exact_string_sequence(payload)
    if intent in {MutationIntent.REMOVE_FIELD, MutationIntent.MOVE}:
        return payload is None
    if intent is MutationIntent.REGISTER:
        if isinstance(payload, RegisterMutationPayload):
            return True
        if not isinstance(payload, Mapping):
            return False
        values = cast("Mapping[object, object]", payload)
        origin = values.get("origin")
        profiles = values.get("profiles", ())
        return isinstance(origin, (str, Origin)) and _is_exact_string_sequence(profiles)
    if intent is MutationIntent.RETIRE_IDENTITY:
        if isinstance(payload, RetirementPayload):
            return True
        if not isinstance(payload, Mapping):
            return False
        values = cast("Mapping[object, object]", payload)
        disposition = values.get("disposition")
        retired_on = values.get("retired_on")
        successor = values.get("successor")
        return (
            type(disposition) is str
            and isinstance(retired_on, (str, date))
            and (successor is None or type(successor) is str)
        )
    return isinstance(payload, (CatalogEntry, Mapping))


def _is_exact_string_sequence(value: object) -> bool:
    """Accept only JSON/Python array carriers containing actual strings."""
    if not isinstance(value, (list, tuple)):
        return False
    items = cast("list[object] | tuple[object, ...]", value)
    return all(type(item) is str for item in items)


class RegistrationRequest(FrozenModel):
    """Inputs for registration of an existing Markdown note."""

    note: str
    collection: str
    actor: str
    task: str
    origin: Origin
    requested_id: str | None = None
    profiles: tuple[str, ...] = ()
    expected_git_revision: str | None = None
    trust_policy: TrustPolicy | None = None
    trust_grant: TrustGrant | None = None
    expected_policy_id: str | None = None
    expected_policy_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class MutationPlan(FrozenModel):
    """Immutable preview and compare-and-swap mutation contract."""

    schema_version: Literal[1] = SCHEMA_VERSION
    operation_id: str
    plan_sha256: str
    intent: MutationIntent
    actor: str
    task: str
    collection: str
    collection_id: str
    collection_snapshot_sha256: str
    intent_payload_json: str
    semantic_unit: str
    expected_git_revision: str | None = None
    preconditions: tuple[FilePrecondition, ...]
    files: tuple[PlannedFile, ...]
    reservations: tuple[IdentityReservation, ...] = ()
    policy_sha256: str | None = None
    configuration_sha256: str | None = None
    profile_lock_sha256: str | None = None
    catalog_sha256: str | None = None
    grant_sha256: str | None = None
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class MutationApproval:
    """In-process owner approval bound to an exact mutation decision."""

    principal: str
    operation_id: str
    plan_sha256: str
    collection_snapshot_sha256: str
    policy_sha256: str | None
    action: str
    approved_at: datetime


@dataclass(frozen=True, slots=True)
class ApplyContext:
    """Runtime conditions supplied when applying a mutation plan."""

    principal: AuthenticatedPrincipal
    expected_operation_id: str
    trust_policy: TrustPolicy | None = None
    trust_grant: TrustGrant | None = None
    approval: MutationApproval | None = None
    recover_lock: bool = False


class ApplyResult(FrozenModel):
    """Successful mutation application result."""

    schema_version: Literal[1] = SCHEMA_VERSION
    operation_id: str
    written_paths: tuple[str, ...]


class ReviewBasis(FrozenModel):
    """Digest of review-relevant normalized Markdown."""

    algorithm: Literal["sha256"] = "sha256"
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @property
    def reference(self) -> str:
        """Return the serialized review-basis reference."""
        return f"sha256:{self.digest}"


class ProjectionRecipe(FrozenModel):
    """Versioned recipe for a rebuildable derived projection."""

    version: Literal[1] = SCHEMA_VERSION
    id: str
    collections: tuple[str, ...]
    admitted_review_statuses: tuple[ReviewStatus, ...]
    trust_domains: frozenset[str]
    chunker: str
    graph_predicates: tuple[str, ...] = ()


class ProjectionRecipeRegistry(FrozenModel):
    """Owner-selected rebuildable projection recipes."""

    version: Literal[1] = SCHEMA_VERSION
    recipes: tuple[ProjectionRecipe, ...] = ()


class ControlManifest(FrozenModel):
    """Contained file manifest for one control authority repository."""

    version: Literal[1] = SCHEMA_VERSION
    control_id: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    owner: str = Field(min_length=1)
    catalog: str
    trust_domains: str
    trust_policy: str
    grants: str
    semantic_releases: str
    projection_recipes: str


class ControlInspectRequest(FrozenModel):
    """Inputs for read-only control authority inspection."""

    root: str


class ControlValidateRequest(ControlInspectRequest):
    """Inputs for read-only control authority validation."""


class ControlInspectionReport(FrozenModel):
    """Read-only control bundle snapshot and diagnostics."""

    schema_version: Literal[1] = SCHEMA_VERSION
    control_root: str
    manifest: ControlManifest | None = None
    catalog: CollectionCatalog | None = None
    trust_domains: TrustDomainRegistry | None = None
    trust_policy: TrustPolicy | None = None
    grants: GrantRegistry | None = None
    semantic_releases: SemanticReleaseRegistry | None = None
    projection_recipes: ProjectionRecipeRegistry | None = None
    bundle_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    knowledge_system_version: str
    knowledge_system_revision: str
    exported_schema_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    findings: tuple[Finding, ...] = ()


class ControlValidationReport(FrozenModel):
    """Control authority validation results and compatibility identity."""

    schema_version: Literal[1] = SCHEMA_VERSION
    control_root: str
    bundle_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    knowledge_system_version: str
    knowledge_system_revision: str
    exported_schema_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    findings: tuple[Finding, ...] = ()

    @property
    def has_blocking_findings(self) -> bool:
        """Return whether error or critical findings prevent acceptance."""
        return any(f.severity in {Severity.ERROR, Severity.CRITICAL} for f in self.findings)


class RevisionAttestation(FrozenModel):
    """Projection proof binding a canonical revision to reviewed content."""

    canonical_revision: str
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    review_basis: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    review_status: ReviewStatus
    attested_at: datetime

    @field_validator("attested_at")
    @classmethod
    def attested_at_is_aware_utc(cls, value: datetime) -> datetime:
        """Normalize projection attestations to aware UTC."""
        return _aware_utc(value)


class IngestionRecord(FrozenModel):
    """Trace from a derived record to canonical Markdown."""

    projection: str
    canonical_reference: str
    revision: str
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    trust_domains: frozenset[str]
    ingested_at: datetime
    attestation: RevisionAttestation
    deleted: bool = False

    @field_validator("ingested_at")
    @classmethod
    def ingested_at_is_aware_utc(cls, value: datetime) -> datetime:
        """Normalize ingestion time to aware UTC."""
        return _aware_utc(value)

    @model_validator(mode="after")
    def attestation_matches_ingestion(self) -> IngestionRecord:
        """Bind the projected revision and digest to the nested attestation."""
        if (
            self.revision != self.attestation.canonical_revision
            or self.content_sha256 != self.attestation.content_sha256
        ):
            raise ValueError("ingestion revision and content digest must match its attestation")
        return self


class ChunkRecord(FrozenModel):
    """Rebuildable retrieval chunk with exact canonical provenance."""

    id: str
    ingestion: IngestionRecord
    heading: str | None = None
    block: str | None = None
    text: str
    ordinal: int = Field(ge=0)


class GraphProjectionEdge(FrozenModel):
    """Derived graph edge that never becomes canonical authority."""

    source: str
    predicate: str
    target: str
    asserted: bool
    provenance: tuple[str, ...]
