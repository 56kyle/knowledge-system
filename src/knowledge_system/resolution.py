"""Canonical reference parsing and resolution for knowledge_system."""

from __future__ import annotations

import json
import re
from hashlib import sha256
from pathlib import Path
from typing import Literal
from typing import cast
from urllib.parse import unquote
from urllib.parse import urlparse

from knowledge_system.collection import inspect_root
from knowledge_system.domain import CanonicalReference
from knowledge_system.domain import RelationResolution
from knowledge_system.domain import ResolutionContext
from knowledge_system.domain import ResolutionResult
from knowledge_system.domain import TrustPolicy
from knowledge_system.exceptions import AuthorizationError
from knowledge_system.exceptions import ConfigurationError
from knowledge_system.exceptions import ReferenceResolutionError
from knowledge_system.exceptions import ReferenceSyntaxError
from knowledge_system.semantic import load_semantic_bundle
from knowledge_system.trust import relation_is_allowed


_NOTE_REFERENCE = re.compile(
    r"^note:(?P<collection>[a-z0-9]+(?:-[a-z0-9]+)*)/(?P<id>[a-z0-9]+(?:-[a-z0-9]+)*)(?:#\^(?P<block>[A-Za-z0-9][A-Za-z0-9_-]*))?$"
)
_ENTITY_REFERENCE = re.compile(
    r"^(?P<scheme>source|source-version|capture|asset|workflow):(?P<id>[A-Za-z0-9][A-Za-z0-9._/-]*)$"
)


def parse_reference(value: str) -> CanonicalReference:
    """Parse one canonical reference or raise ReferenceSyntaxError."""
    note_match = _NOTE_REFERENCE.fullmatch(value)
    if note_match:
        return CanonicalReference(
            scheme="note",
            collection=note_match.group("collection"),
            identifier=note_match.group("id"),
            block=note_match.group("block"),
        )
    entity_match = _ENTITY_REFERENCE.fullmatch(value)
    if entity_match:
        return CanonicalReference(
            scheme=cast(
                "Literal['source', 'source-version', 'capture', 'asset', 'workflow']",
                entity_match.group("scheme"),
            ),
            identifier=entity_match.group("id"),
        )
    raise ReferenceSyntaxError(f"invalid canonical reference: {value}")


def resolve_reference(
    reference: CanonicalReference,
    context: ResolutionContext,
) -> ResolutionResult:
    """Resolve an authorized note reference using deployment locators."""
    if reference.scheme != "note" or reference.collection is None:
        raise ReferenceResolutionError(f"no local resolver for {reference.scheme} references")
    if reference.collection not in context.allowed_collections:
        raise AuthorizationError("reference resolution is not authorized")
    entries = [entry for entry in context.catalog.collections if entry.collection_id == reference.collection]
    if len(entries) != 1:
        raise ReferenceResolutionError(f"collection is not uniquely cataloged: {reference.collection}")
    entry = entries[0]
    manifest_path = _resolve_manifest_locator(entry.manifest, entry.repo_root, context)
    collection_root = manifest_path.parent
    inspection = inspect_root(collection_root, manifest_path=manifest_path)
    if inspection.manifest is None or inspection.manifest.collection.id != entry.collection_id:
        raise ReferenceResolutionError("catalog entry does not match the target manifest identity")
    manifest_domains = frozenset({inspection.manifest.collection.trust_domain})
    if entry.trust_domains != manifest_domains:
        raise ReferenceResolutionError("catalog trust domains do not match the target manifest")
    matches = [note for note in inspection.notes if note.envelope and note.envelope.id == reference.identifier]
    if len(matches) != 1:
        raise ReferenceResolutionError(f"note is not uniquely resolved: {reference.identifier}")
    note = matches[0]
    if reference.block is not None and reference.block not in note.block_ids:
        raise ReferenceResolutionError(f"block does not resolve: {reference.block}")
    return ResolutionResult(reference=reference, path=str(collection_root / note.path))


def resolve_reference_effective_domains(  # noqa: C901
    reference: CanonicalReference,
    context: ResolutionContext,
    policy: TrustPolicy,
    *,
    source_domains: frozenset[str],
    predicate: str,
) -> ResolutionResult:
    """Resolve a note and every canonical dependency under opaque authorization."""
    if reference.collection is None:
        raise ReferenceResolutionError("reference dependency is unavailable")
    catalog_domains = _catalog_domains(reference.collection, context)
    if not relation_is_allowed(
        policy,
        source_domains=source_domains,
        destination_domains=catalog_domains,
        predicate=predicate,
    ):
        raise AuthorizationError("reference dependency is unavailable")
    queue = [reference]
    domains: dict[str, set[str]] = {}
    edges: list[tuple[str, str, str]] = []
    revisions: dict[str, str] = {}
    paths: dict[str, str] = {}
    while queue:
        current = queue.pop()
        key = f"note:{current.collection}/{current.identifier}"
        if key in domains:
            continue
        try:
            result = resolve_reference(current, context)
            root = Path(result.path).parent
            entry_domains = _catalog_domains(cast("str", current.collection), context)
            collection_root = _collection_root_for(cast("str", current.collection), context)
            inspection = inspect_root(collection_root)
            if inspection.manifest is None:
                raise ReferenceResolutionError("reference dependency is unavailable")
            semantic_bundle = load_semantic_bundle(collection_root, inspection.manifest)
            note = next(
                item
                for item in inspection.notes
                if item.envelope is not None and item.envelope.id == current.identifier
            )
        except (
            ConfigurationError,
            OSError,
            StopIteration,
            AuthorizationError,
            ReferenceResolutionError,
            ValueError,
        ) as error:
            raise ReferenceResolutionError("reference dependency is unavailable") from error
        del root
        domains[key] = set(entry_domains)
        revisions[key] = note.content_sha256
        paths[key] = result.path
        envelope = note.envelope
        if envelope is None:
            raise ReferenceResolutionError("reference dependency is unavailable")
        dependencies: list[tuple[str, str, bool]] = []
        for relation in envelope.relations:
            predicate_contract = semantic_bundle.predicates.get(relation.predicate)
            resolution = relation.resolution or (
                predicate_contract.default_resolution
                if predicate_contract is not None and predicate_contract.default_resolution is not None
                else RelationResolution(inspection.manifest.relations.default_resolution)
            )
            dependencies.append((relation.target, relation.predicate, resolution is RelationResolution.REQUIRED))
        dependencies.extend((value, "derived_from", True) for value in (*envelope.sources, *envelope.led_to))
        if envelope.up is not None:
            dependencies.append((envelope.up, "up", True))
        for value, dependency_predicate, required in dependencies:
            try:
                dependency = parse_reference(value)
            except ReferenceSyntaxError:
                continue
            if dependency.scheme != "note" or dependency.collection is None:
                continue
            if not required:
                try:
                    _ = resolve_reference(dependency, context)
                except (AuthorizationError, ReferenceResolutionError, OSError, ValueError):
                    continue
            dependency_domains = _catalog_domains(dependency.collection, context)
            if not relation_is_allowed(
                policy,
                source_domains=entry_domains,
                destination_domains=dependency_domains,
                predicate=dependency_predicate,
            ):
                if not required:
                    continue
                raise AuthorizationError("reference dependency is unavailable")
            dependency_key = f"note:{dependency.collection}/{dependency.identifier}"
            edges.append((key, dependency_key, dependency_predicate))
            queue.append(dependency)
    changed = True
    while changed:
        changed = False
        for source, target, _edge_predicate in edges:
            before = len(domains[source])
            domains[source].update(domains[target])
            changed = changed or len(domains[source]) != before
    for source, target, edge_predicate in edges:
        if not relation_is_allowed(
            policy,
            source_domains=frozenset(domains[source]),
            destination_domains=frozenset(domains[target]),
            predicate=edge_predicate,
        ):
            raise AuthorizationError("reference dependency is unavailable")
    initial = f"note:{reference.collection}/{reference.identifier}"
    effective = frozenset(domains[initial])
    if not relation_is_allowed(
        policy,
        source_domains=source_domains,
        destination_domains=effective,
        predicate=predicate,
    ):
        raise AuthorizationError("reference dependency is unavailable")
    attestation = sha256(
        json.dumps({"domains": sorted(effective), "revisions": revisions}, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return ResolutionResult(
        reference=reference,
        path=paths[initial],
        effective_domains=effective,
        revision_attestation_sha256=attestation,
    )


def _catalog_domains(collection: str, context: ResolutionContext) -> frozenset[str]:
    """Return owner-authoritative primary domains without opening a target."""
    entries = [entry for entry in context.catalog.collections if entry.collection_id == collection]
    if len(entries) != 1 or collection not in context.allowed_collections:
        raise AuthorizationError("reference dependency is unavailable")
    return entries[0].trust_domains


def _collection_root_for(collection: str, context: ResolutionContext) -> Path:
    """Resolve an authorized collection root after its catalog decision."""
    entries = [entry for entry in context.catalog.collections if entry.collection_id == collection]
    if len(entries) != 1:
        raise ReferenceResolutionError("reference dependency is unavailable")
    return _resolve_manifest_locator(entries[0].manifest, entries[0].repo_root, context).parent


def _resolve_manifest_locator(  # noqa: C901
    locator: str,
    legacy_repo_root: str | None,
    context: ResolutionContext,
) -> Path:
    """Resolve catalog-relative, repo, or explicitly allowed file locators."""
    parsed = urlparse(locator)
    if parsed.scheme == "repo":
        root_name = parsed.netloc
        if not root_name or root_name not in context.repo_roots:
            raise ReferenceResolutionError("repo locator names an unknown configured root")
        root = Path(context.repo_roots[root_name]).resolve(strict=True)
        relative = Path(unquote(parsed.path.lstrip("/")))
    elif parsed.scheme == "file":
        file_path = unquote(parsed.path)
        if re.match(r"^/[A-Za-z]:/", file_path):
            file_path = file_path[1:]
        candidate = Path(file_path)
        if re.fullmatch(r"[A-Za-z]:.*", str(candidate)) is None and parsed.netloc:
            candidate = Path(f"//{parsed.netloc}/{unquote(parsed.path.lstrip('/'))}")
        resolved = candidate.resolve(strict=True)
        allowed = tuple(Path(value).resolve(strict=True) for value in context.allowed_file_roots)
        if not allowed or not any(resolved.is_relative_to(root) for root in allowed):
            raise AuthorizationError("file locator is outside explicitly allowed roots")
        return resolved
    elif parsed.scheme:
        raise ReferenceResolutionError(f"unsupported manifest locator scheme: {parsed.scheme}")
    elif legacy_repo_root is not None:
        if legacy_repo_root not in context.repo_roots:
            raise ReferenceResolutionError("catalog entry names an unknown configured root")
        root = Path(context.repo_roots[legacy_repo_root]).resolve(strict=True)
        relative = Path(locator)
    else:
        root = Path(context.catalog_root).resolve(strict=True)
        relative = Path(locator)
    if relative.is_absolute() or ".." in relative.parts:
        raise ReferenceResolutionError("manifest locator must not escape its configured root")
    resolved = (root / relative).resolve(strict=True)
    if not resolved.is_relative_to(root):
        raise ReferenceResolutionError("manifest locator escapes its configured root")
    return resolved
