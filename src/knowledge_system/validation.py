"""Pure collection validation for the knowledge_system package."""

from __future__ import annotations

import json
from collections import Counter
from collections import defaultdict
from collections.abc import Mapping
from datetime import date
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import cast

from pydantic import ValidationError

from knowledge_system.codec import load_yaml_mapping
from knowledge_system.codec import plain_mapping
from knowledge_system.collection import inspect_root
from knowledge_system.domain import CanonicalReference
from knowledge_system.domain import CollectionCatalog
from knowledge_system.domain import Finding
from knowledge_system.domain import PredicateDefinition
from knowledge_system.domain import ProvenanceRegistry
from knowledge_system.domain import RelationResolution
from knowledge_system.domain import ResolutionContext
from knowledge_system.domain import RetiredIdentityFile
from knowledge_system.domain import RetirementRecord
from knowledge_system.domain import Severity
from knowledge_system.domain import TrustPolicy
from knowledge_system.domain import ValidateRequest
from knowledge_system.domain import ValidationReport
from knowledge_system.exceptions import AuthorizationError
from knowledge_system.exceptions import ConfigurationError
from knowledge_system.exceptions import ReferenceResolutionError
from knowledge_system.profiles import validate_profiles
from knowledge_system.resolution import parse_reference
from knowledge_system.resolution import resolve_reference_effective_domains
from knowledge_system.semantic import SemanticBundle
from knowledge_system.semantic import load_semantic_bundle
from knowledge_system.trust import relation_is_allowed


def validate_root(  # noqa: C901
    root: Path,
    *,
    manifest_path: Path | None = None,
) -> ValidationReport:
    """Validate a collection snapshot without changing files or timestamps."""
    inspection = inspect_root(root, manifest_path=manifest_path)
    findings = list(inspection.findings)
    manifest = inspection.manifest
    identities = [note.envelope.id for note in inspection.notes if note.envelope]
    identity_counts = Counter(identities)
    for identity, count in sorted(identity_counts.items()):
        if count > 1:
            findings.append(
                Finding(
                    severity=Severity.ERROR,
                    code="identity.duplicate",
                    message=f"identity {identity} occurs {count} times",
                )
            )
    retired = _retired_identities(root, findings)
    for note in inspection.notes:
        envelope = note.envelope
        if envelope is None or envelope.id not in retired:
            continue
        retirement = retired[envelope.id]
        note_retirement = note.properties.get("retirement")
        retirement_values: Mapping[object, object] = (
            cast("Mapping[object, object]", note_retirement) if isinstance(note_retirement, Mapping) else {}
        )
        retained_date: object | None = (
            retirement_values.get("retired_on") or retirement_values.get("retired_at") or retirement_values.get("date")
        )
        retained_date_text = _retirement_date_text(retained_date)
        matching_tombstone = (
            envelope.record_status.value in {"retired", "superseded"}
            and isinstance(note_retirement, Mapping)
            and retirement_values.get("disposition") == retirement.disposition
            and retirement_values.get("successor") == retirement.successor
            and retained_date_text == retirement.retired_on.isoformat()
        )
        if not matching_tombstone:
            findings.append(
                Finding(
                    severity=Severity.ERROR,
                    code="identity.retired-reused",
                    message=f"active or mismatched note reuses retired identity: {envelope.id}",
                    path=note.path,
                )
            )
    semantic_bundle: SemanticBundle | None = None
    if manifest is not None:
        try:
            semantic_bundle = load_semantic_bundle(root, manifest)
        except (ConfigurationError, OSError, ValueError) as error:
            findings.append(
                Finding(
                    severity=Severity.ERROR,
                    code="semantic.bundle-invalid",
                    message=str(error),
                    path="profiles.lock.yaml",
                )
            )
        _validate_registries(root, manifest, inspection.notes, findings)
    by_reference = {
        f"note:{manifest.collection.id}/{note.envelope.id}": note
        for note in inspection.notes
        if manifest is not None and note.envelope is not None
    }
    structural: dict[str, str] = {}
    allowed_predicates: Mapping[str, PredicateDefinition] = (
        semantic_bundle.predicates if semantic_bundle is not None else {}
    )
    for note in inspection.notes:
        findings.extend(validate_profiles(note, manifest))
        envelope = note.envelope
        if envelope is None:
            continue
        for relation in envelope.relations:
            if relation.predicate not in allowed_predicates:
                findings.append(
                    Finding(
                        severity=Severity.ERROR,
                        code="relation.predicate-unlocked",
                        message=f"predicate is not in a locked vocabulary: {relation.predicate}",
                        path=note.path,
                        line=1,
                    )
                )
            try:
                reference = parse_reference(relation.target)
            except ValueError:
                findings.append(
                    Finding(
                        severity=Severity.ERROR,
                        code="relation.reference-invalid",
                        message=f"invalid target: {relation.target}",
                        path=note.path,
                        line=1,
                    )
                )
                continue
            predicate_definition = allowed_predicates.get(relation.predicate)
            resolution = relation.resolution or (
                predicate_definition.default_resolution
                if predicate_definition is not None and predicate_definition.default_resolution is not None
                else RelationResolution(manifest.relations.default_resolution)
                if manifest is not None
                else RelationResolution.REQUIRED
            )
            if resolution is RelationResolution.PROSPECTIVE and not (
                (predicate_definition is not None and predicate_definition.prospective_allowed)
                or (manifest is not None and relation.predicate in manifest.relations.prospective_predicates)
            ):
                findings.append(
                    Finding(
                        severity=Severity.ERROR,
                        code="relation.prospective-forbidden",
                        message=f"predicate does not permit prospective targets: {relation.predicate}",
                        path=note.path,
                        line=1,
                    )
                )
            target_key = relation.target.split("#", maxsplit=1)[0]
            if (
                reference.scheme == "note"
                and reference.collection == (manifest.collection.id if manifest else None)
                and target_key not in by_reference
            ):
                findings.append(
                    Finding(
                        severity=(Severity.ERROR if resolution is RelationResolution.REQUIRED else Severity.WARNING),
                        code=(
                            "relation.target-missing"
                            if resolution is RelationResolution.REQUIRED
                            else "relation.target-prospective"
                        ),
                        message=f"target does not resolve: {relation.target}",
                        path=note.path,
                        line=1,
                    )
                )
            elif reference.block is not None and target_key in by_reference:
                target_note = by_reference[target_key]
                if reference.block not in target_note.block_ids:
                    findings.append(
                        Finding(
                            severity=Severity.ERROR,
                            code="relation.block-missing",
                            message=f"target block does not resolve: {relation.target}",
                            path=note.path,
                            line=1,
                        )
                    )
        findings.extend(_validate_provenance(note, manifest, by_reference))
        if envelope.up and manifest is not None:
            source = f"note:{manifest.collection.id}/{envelope.id}"
            try:
                up_reference = parse_reference(envelope.up)
            except ValueError:
                findings.append(
                    Finding(
                        severity=Severity.ERROR,
                        code="structure.up-invalid",
                        message="up must be a canonical note reference",
                        path=note.path,
                        line=1,
                    )
                )
            else:
                target = envelope.up.split("#", maxsplit=1)[0]
                if target == source:
                    findings.append(
                        Finding(
                            severity=Severity.ERROR,
                            code="structure.up-self",
                            message="up must not reference the note itself",
                            path=note.path,
                            line=1,
                        )
                    )
                elif up_reference.scheme != "note" or target not in by_reference:
                    findings.append(
                        Finding(
                            severity=Severity.ERROR,
                            code="structure.up-missing",
                            message="up must resolve to a registered note",
                            path=note.path,
                            line=1,
                        )
                    )
                else:
                    structural[source] = target
    findings.extend(_cycle_findings(structural))
    if semantic_bundle is not None:
        _validate_loaded_custom_profiles(inspection.notes, semantic_bundle, findings)
    return ValidationReport(
        collection_root=inspection.collection_root,
        findings=tuple(sorted(findings, key=lambda item: (item.path or "", item.line or 0, item.code))),
    )


def validate_external_context(  # noqa: C901
    request: ValidateRequest,
    report: ValidationReport,
) -> ValidationReport:
    """Validate cross-collection relations using explicit catalog and trust inputs."""
    root = Path(request.collection).resolve(strict=True)
    inspection = inspect_root(root, manifest_path=Path(request.manifest) if request.manifest else None)
    manifest = inspection.manifest
    if manifest is None:
        return report
    foreign = [
        (note, relation, reference)
        for note in inspection.notes
        if note.envelope is not None
        for relation in note.envelope.relations
        for reference in (_parsed_or_none(relation.target),)
        if reference is not None and reference.scheme == "note" and reference.collection != manifest.collection.id
    ]
    if not foreign:
        return report
    findings = list(report.findings)
    if request.catalog is None or (manifest.references.trust_policy is None and request.external_policy is None):
        findings.extend(
            Finding(
                severity=Severity.ERROR,
                code="relation.cross-domain-policy-unavailable",
                message="cross-collection relations require catalog and trust policy inputs",
                path=note.path,
                line=1,
            )
            for note, _relation, _reference in foreign
        )
        return ValidationReport(collection_root=report.collection_root, findings=tuple(findings))
    try:
        catalog_path = Path(request.catalog).resolve(strict=True)
        catalog = CollectionCatalog.model_validate(
            plain_mapping(load_yaml_mapping(catalog_path.read_text(encoding="utf-8"), source=str(catalog_path)))
        )
        declared_policy: TrustPolicy | None = None
        if manifest.references.trust_policy is not None:
            relative_policy = Path(manifest.references.trust_policy)
            if relative_policy.is_absolute() or ".." in relative_policy.parts:
                raise ValueError("manifest trust policy path escapes collection")
            policy_path = (root / relative_policy).resolve(strict=True)
            if not policy_path.is_relative_to(root) or policy_path.is_symlink():
                raise ValueError("manifest trust policy path escapes collection")
            declared_policy = TrustPolicy.model_validate(
                plain_mapping(load_yaml_mapping(policy_path.read_text(encoding="utf-8"), source=str(policy_path)))
            )
        external_policy = request.external_policy
        if external_policy is not None:
            digest = sha256(
                json.dumps(external_policy.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode(
                    "utf-8"
                )
            ).hexdigest()
            if request.expected_policy_id != external_policy.id or request.expected_policy_sha256 != digest:
                raise ValueError("external policy identity or digest does not match its expectation")
            if declared_policy is not None and declared_policy != external_policy:
                raise ValueError("external policy disagrees with manifest-declared policy")
        policy = external_policy or declared_policy
        if policy is None:
            raise ValueError("trust policy is unavailable")
        if (
            manifest.references.trust_policy_id is not None
            and request.expected_policy_id is not None
            and manifest.references.trust_policy_id != request.expected_policy_id
        ):
            raise ValueError("manifest and external policy identity expectations disagree")
        bound_policy_id = manifest.references.trust_policy_id or request.expected_policy_id
        if bound_policy_id is None or policy.id != bound_policy_id:
            raise ValueError("trust policy identity does not match collection binding")
    except (OSError, ValidationError, ValueError) as error:
        findings.append(
            Finding(
                severity=Severity.ERROR,
                code="relation.cross-domain-context-invalid",
                message=str(error),
            )
        )
        return ValidationReport(collection_root=report.collection_root, findings=tuple(findings))
    context = ResolutionContext(
        catalog=catalog,
        catalog_root=str(catalog_path.parent),
        repo_roots=dict(request.repo_roots),
        allowed_collections=tuple(entry.collection_id for entry in catalog.collections),
    )
    destination_domains: dict[str, frozenset[str]] = {}
    for note, relation, reference in foreign:
        if reference.collection is None:
            continue
        destination = destination_domains.get(reference.collection)
        if destination is None:
            try:
                destination = _catalog_collection_domains(reference.collection, context)
            except (OSError, ValueError) as error:
                findings.append(
                    Finding(
                        severity=Severity.ERROR,
                        code="relation.destination-context-invalid",
                        message=str(error),
                        path=note.path,
                        line=1,
                    )
                )
                continue
            destination_domains[reference.collection] = destination
        source = frozenset({manifest.collection.trust_domain})
        if not relation_is_allowed(
            policy,
            source_domains=source,
            destination_domains=destination,
            predicate=relation.predicate,
        ):
            findings.append(
                Finding(
                    severity=Severity.ERROR,
                    code="relation.cross-domain-denied",
                    message=f"cross-domain predicate is not allowed: {relation.predicate}",
                    path=note.path,
                    line=1,
                )
            )
            continue
        resolution = relation.resolution or RelationResolution(manifest.relations.default_resolution)
        if resolution is RelationResolution.REQUIRED:
            try:
                _ = resolve_reference_effective_domains(
                    reference,
                    context,
                    policy,
                    source_domains=source,
                    predicate=relation.predicate,
                )
            except (AuthorizationError, ReferenceResolutionError, OSError, ValueError):
                findings.append(
                    Finding(
                        severity=Severity.ERROR,
                        code="relation.external-target-unavailable",
                        message="external target is missing or unauthorized",
                        path=note.path,
                        line=1,
                    )
                )
    return ValidationReport(
        collection_root=report.collection_root,
        findings=tuple(sorted(findings, key=lambda item: (item.path or "", item.line or 0, item.code))),
    )


def _parsed_or_none(value: str) -> CanonicalReference | None:
    """Parse a relation target for contextual validation when canonical."""
    try:
        return parse_reference(value)
    except ValueError:
        return None


def _catalog_collection_domains(
    collection_id: str,
    context: ResolutionContext,
) -> frozenset[str]:
    """Load a cataloged collection's declared base domain."""
    entries = [entry for entry in context.catalog.collections if entry.collection_id == collection_id]
    if len(entries) != 1:
        return frozenset()
    return entries[0].trust_domains


def _retired_identities(root: Path, findings: list[Finding]) -> Mapping[str, RetirementRecord]:
    """Load retired identities, reporting invalid ledgers."""
    path = root / "retired-ids.yaml"
    if not path.exists():
        return {}
    try:
        model = RetiredIdentityFile.model_validate(
            plain_mapping(load_yaml_mapping(path.read_text(encoding="utf-8"), source=str(path)))
        )
    except (OSError, ValidationError, ValueError) as error:
        findings.append(
            Finding(
                severity=Severity.ERROR,
                code="identity.retired-ledger-invalid",
                message=str(error),
                path="retired-ids.yaml",
            )
        )
        return {}
    for record in model.records:
        if record.successor is None:
            continue
        try:
            successor = parse_reference(record.successor)
        except ValueError:
            successor = None
        if successor is None or successor.scheme != "note":
            findings.append(
                Finding(
                    severity=Severity.ERROR,
                    code="identity.retired-successor-invalid",
                    message=f"retired successor is not a canonical note reference: {record.id}",
                    path="retired-ids.yaml",
                )
            )
    return {record.id: record for record in model.records}


def _retirement_date_text(value: object | None) -> str | None:
    """Normalize supported tombstone date aliases to one calendar date."""
    if isinstance(value, datetime):
        return value.date().isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value).isoformat()
    except ValueError:
        try:
            return datetime.fromisoformat(value).date().isoformat()
        except ValueError:
            return None


def _validate_registries(  # noqa: C901
    root: Path,
    manifest: object,
    notes: tuple[object, ...],
    findings: list[Finding],
) -> None:
    """Validate contained provenance registries and their declared states."""
    from knowledge_system.domain import CollectionManifest
    from knowledge_system.domain import CollectionNote

    if not isinstance(manifest, CollectionManifest):
        return
    references = (
        (manifest.references.source_registry, "source"),
        (manifest.references.source_version_registry, "source-version"),
        (manifest.references.capture_registry, "capture"),
        (manifest.references.asset_registry, "asset"),
    )
    states: dict[str, str] = {}
    seen_references: set[str] = set()
    configured_schemes: set[str] = set()
    collection_root = root.resolve(strict=True)
    for reference, expected_scheme in references:
        if reference is None:
            continue
        configured_schemes.add(expected_scheme)
        relative = Path(reference)
        if relative.is_absolute() or ".." in relative.parts:
            findings.append(
                Finding(
                    severity=Severity.ERROR, code="registry.path-invalid", message="registry path escapes collection"
                )
            )
            continue
        try:
            path = (collection_root / relative).resolve(strict=True)
            if not path.is_relative_to(collection_root):
                raise ValueError("registry path escapes collection")
            registry = ProvenanceRegistry.model_validate(
                plain_mapping(load_yaml_mapping(path.read_text(encoding="utf-8"), source=str(path)))
            )
        except (OSError, ValidationError, ValueError) as error:
            findings.append(
                Finding(severity=Severity.ERROR, code="registry.invalid", message=str(error), path=reference)
            )
            continue
        for entry in registry.entries:
            ambiguous = entry.reference in seen_references
            if ambiguous:
                findings.append(
                    Finding(
                        severity=Severity.ERROR,
                        code="registry.reference-ambiguous",
                        message=f"provenance identity appears in multiple registries: {entry.reference}",
                        path=reference,
                    )
                )
            seen_references.add(entry.reference)
            try:
                parsed = parse_reference(entry.reference)
            except ValueError:
                parsed = None
            if parsed is None or parsed.scheme != expected_scheme:
                findings.append(
                    Finding(
                        severity=Severity.ERROR,
                        code="registry.scheme-invalid",
                        message=f"registry entry must use {expected_scheme}: {entry.reference}",
                        path=reference,
                    )
                )
                continue
            if ambiguous:
                continue
            states[entry.reference] = entry.status
            severity = Severity.WARNING if entry.status in {"unavailable", "unverifiable"} else Severity.ERROR
            if entry.status != "verified":
                findings.append(
                    Finding(
                        severity=severity,
                        code=f"registry.{entry.status.replace('_', '-')}",
                        message=f"provenance record is {entry.status}: {entry.reference}",
                        path=reference,
                    )
                )
    for value in notes:
        if not isinstance(value, CollectionNote) or value.envelope is None:
            continue
        envelope = value.envelope
        evidence = tuple(
            dict.fromkeys(
                (
                    *envelope.sources,
                    *((envelope.source_version,) if envelope.source_version is not None else ()),
                    *envelope.captures,
                    *envelope.assets,
                )
            )
        )
        for item in evidence:
            reference = _parsed_or_none(item)
            if reference is None or reference.scheme not in configured_schemes:
                continue
            if item not in states:
                findings.append(
                    Finding(
                        severity=Severity.ERROR,
                        code="registry.evidence-missing",
                        message=f"configured registry does not account for evidence: {item}",
                        path=value.path,
                    )
                )
        if (
            envelope.review.status.value == "reviewed"
            and envelope.epistemic_status is not None
            and envelope.epistemic_status.value == "supported"
            and evidence
            and all(states.get(item) == "unverifiable" for item in evidence)
        ):
            findings.append(
                Finding(
                    severity=Severity.ERROR,
                    code="provenance.review-support-unverifiable",
                    message="a reviewed supported claim cannot rely only on unverifiable evidence",
                    path=value.path,
                )
            )


def _validate_loaded_custom_profiles(  # noqa: C901
    notes: tuple[object, ...],
    bundle: SemanticBundle,
    findings: list[Finding],
) -> None:
    """Validate note fields against the already verified semantic bundle."""
    from knowledge_system.domain import CollectionNote

    definitions = bundle.profiles
    for value in notes:
        if not isinstance(value, CollectionNote) or value.envelope is None:
            continue
        selected = [definitions[profile] for profile in value.envelope.profiles if profile in definitions]
        owners: dict[str, str] = {}
        for definition in selected:
            for field in definition.fields:
                previous = owners.setdefault(field.name, definition.id)
                if previous != definition.id:
                    findings.append(
                        Finding(
                            severity=Severity.ERROR,
                            code="profile.field-conflict",
                            message=f"field {field.name} is owned by {previous} and {definition.id}",
                            path=value.path,
                            line=1,
                        )
                    )
                present = field.name in value.properties
                if field.required and not present:
                    findings.append(
                        Finding(
                            severity=Severity.ERROR,
                            code="profile.field-required",
                            message=f"profile {definition.id} requires {field.name}",
                            path=value.path,
                            line=1,
                        )
                    )
                if present and not _field_matches(value.properties[field.name], field.type, field.enum):
                    findings.append(
                        Finding(
                            severity=Severity.ERROR,
                            code="profile.field-invalid",
                            message=f"field {field.name} does not match its profile contract",
                            path=value.path,
                            line=1,
                        )
                    )
            present_fields = {field.name for field in definition.fields if field.name in value.properties}
            for invariant in definition.invariants:
                selected_fields = set(invariant.fields).intersection(present_fields)
                valid = True
                if invariant.kind == "required_together":
                    valid = not selected_fields or selected_fields == set(invariant.fields)
                elif invariant.kind == "exactly_one":
                    valid = len(selected_fields) == 1
                elif invariant.kind == "requires":
                    valid = invariant.fields[0] not in present_fields or set(invariant.fields[1:]).issubset(
                        present_fields
                    )
                if not valid:
                    findings.append(
                        Finding(
                            severity=Severity.ERROR,
                            code="profile.invariant-failed",
                            message=f"{definition.id} invariant {invariant.kind} failed",
                            path=value.path,
                            line=1,
                        )
                    )


def _field_matches(value: object, kind: str, enum: tuple[str, ...]) -> bool:
    """Check one declarative field without coercion."""
    if kind == "string":
        valid = isinstance(value, str)
    elif kind == "integer":
        valid = isinstance(value, int) and not isinstance(value, bool)
    elif kind == "boolean":
        valid = isinstance(value, bool)
    elif kind == "string-list":
        valid = isinstance(value, (list, tuple)) and all(
            isinstance(item, str) for item in cast("list[object] | tuple[object, ...]", value)
        )
    else:
        return False
    return valid and (not enum or (isinstance(value, str) and value in enum))


def _validate_provenance(  # noqa: C901
    note: object,
    manifest: object,
    indexed_notes: Mapping[str, object],
) -> tuple[Finding, ...]:
    """Validate canonical provenance schemes and locally resolvable note inputs."""
    from knowledge_system.domain import CollectionManifest
    from knowledge_system.domain import CollectionNote

    if not isinstance(note, CollectionNote) or note.envelope is None:
        return ()
    collection_manifest = manifest if isinstance(manifest, CollectionManifest) else None
    envelope = note.envelope
    findings: list[Finding] = []
    constraints = (
        ("sources", envelope.sources, frozenset({"source-version", "asset", "note"})),
        ("captures", envelope.captures, frozenset({"capture"})),
        ("assets", envelope.assets, frozenset({"asset"})),
        ("led_to", envelope.led_to, frozenset({"note"})),
    )
    for field, values, schemes in constraints:
        for value in values:
            try:
                reference = parse_reference(value)
            except ValueError:
                reference = None
            if reference is None or reference.scheme not in schemes:
                findings.append(
                    Finding(
                        severity=Severity.ERROR,
                        code="provenance.scheme-invalid",
                        message=f"{field} contains an invalid canonical reference: {value}",
                        path=note.path,
                        line=1,
                    )
                )
            elif (
                reference.scheme == "note"
                and collection_manifest is not None
                and reference.collection == collection_manifest.collection.id
            ):
                target_key = value.split("#", maxsplit=1)[0]
                target = indexed_notes.get(target_key)
                if not isinstance(target, CollectionNote) or (
                    reference.block is not None and reference.block not in target.block_ids
                ):
                    findings.append(
                        Finding(
                            severity=Severity.ERROR,
                            code="provenance.local-reference-missing",
                            message=f"local provenance note or block does not resolve: {value}",
                            path=note.path,
                            line=1,
                        )
                    )
    if envelope.source_version is not None:
        try:
            source_version = parse_reference(envelope.source_version)
        except ValueError:
            source_version = None
        if source_version is None or source_version.scheme != "source-version":
            findings.append(
                Finding(
                    severity=Severity.ERROR,
                    code="provenance.source-version-invalid",
                    message="source_version must use the source-version scheme",
                    path=note.path,
                    line=1,
                )
            )
    return tuple(findings)


def _cycle_findings(parents: dict[str, str]) -> list[Finding]:
    """Find structural cycles while memoizing completed traversals."""
    complete: set[str] = set()
    findings: list[Finding] = []
    emitted: set[tuple[str, ...]] = set()
    for start in sorted(parents):
        if start in complete:
            continue
        path: list[str] = []
        position: dict[str, int] = {}
        current: str | None = start
        while current is not None and current not in complete:
            if current in position:
                cycle = (*path[position[current] :], current)
                normalized = min(
                    tuple(cycle[index:-1] + cycle[:index] + (cycle[index],)) for index in range(len(cycle) - 1)
                )
                if normalized not in emitted:
                    emitted.add(normalized)
                    findings.append(
                        Finding(
                            severity=Severity.ERROR,
                            code="structure.cycle",
                            message="structural cycle: " + " -> ".join(cycle),
                        )
                    )
                break
            position[current] = len(path)
            path.append(current)
            current = parents.get(current)
        complete.update(path)
    return findings


def reverse_impact(reference: str, root: Path) -> tuple[str, ...]:
    """Return registered notes that directly or transitively reference a target."""
    inspection = inspect_root(root)
    manifest = inspection.manifest
    if manifest is None:
        return ()
    reverse: dict[str, set[str]] = defaultdict(set)
    for note in inspection.notes:
        if note.envelope is None:
            continue
        source = f"note:{manifest.collection.id}/{note.envelope.id}"
        targets = [relation.target.split("#", maxsplit=1)[0] for relation in note.envelope.relations]
        if note.envelope.up:
            targets.append(note.envelope.up.split("#", maxsplit=1)[0])
        for target in targets:
            reverse[target].add(source)
    affected: set[str] = set()
    pending = [reference.split("#", maxsplit=1)[0]]
    while pending:
        target = pending.pop()
        for source in sorted(reverse.get(target, set())):
            if source not in affected:
                affected.add(source)
                pending.append(source)
    return tuple(sorted(affected))
