"""Previewable compare-and-swap mutations for knowledge_system."""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import socket
import subprocess
import tempfile
import time
import uuid
from base64 import b64decode
from base64 import b64encode
from contextlib import contextmanager
from datetime import datetime
from datetime import timezone
from difflib import unified_diff
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING
from typing import cast

from pydantic import ValidationError

from knowledge_system.authentication import AuthenticatedPrincipal
from knowledge_system.authentication import LocalFilesystemPrincipal
from knowledge_system.codec import dump_yaml_mapping
from knowledge_system.codec import insert_yaml_field
from knowledge_system.codec import load_yaml_mapping
from knowledge_system.codec import new_yaml_mapping
from knowledge_system.codec import parse_markdown
from knowledge_system.codec import plain_mapping
from knowledge_system.codec import render_markdown
from knowledge_system.collection import inspect_root
from knowledge_system.collection import path_matches
from knowledge_system.domain import ApplyContext
from knowledge_system.domain import ApplyResult
from knowledge_system.domain import CatalogEntry
from knowledge_system.domain import CollectionCatalog
from knowledge_system.domain import CollectionManifest
from knowledge_system.domain import CollectionNote
from knowledge_system.domain import FilePrecondition
from knowledge_system.domain import IdentityReservation
from knowledge_system.domain import MutationApproval
from knowledge_system.domain import MutationIntent
from knowledge_system.domain import MutationPlan
from knowledge_system.domain import MutationRequest
from knowledge_system.domain import NoteEnvelope
from knowledge_system.domain import PlannedFile
from knowledge_system.domain import RegisterMutationPayload
from knowledge_system.domain import RegistrationRequest
from knowledge_system.domain import RetiredIdentityFile
from knowledge_system.domain import RetirementPayload
from knowledge_system.domain import TrustGrant
from knowledge_system.domain import TrustPolicy
from knowledge_system.exceptions import ApplyIndeterminateError
from knowledge_system.exceptions import AuthorizationError
from knowledge_system.exceptions import ConfigurationError
from knowledge_system.exceptions import MutationConflictError
from knowledge_system.exceptions import MutationPlanningError
from knowledge_system.profiles import validate_profiles
from knowledge_system.resolution import parse_reference
from knowledge_system.semantic import SemanticBundle
from knowledge_system.semantic import load_semantic_bundle
from knowledge_system.semantic import validate_note_semantics
from knowledge_system.trust import authorize


if TYPE_CHECKING:
    from collections.abc import Generator
    from collections.abc import Mapping


_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_GENERIC_MUTABLE_FIELDS = frozenset({"tags", "aliases"})
_ZERO_DIGEST = "0" * 64
_LOCK_STALE_SECONDS = 300


def _digest(content: bytes) -> str:
    """Return a lowercase SHA-256 digest."""
    return sha256(content).hexdigest()


def _relative_path(value: str) -> Path:
    """Parse a portable collection-relative path without traversal syntax."""
    if not value or "\x00" in value:
        raise MutationPlanningError("path must not be empty or contain NUL")
    if value.startswith(("\\\\", "//", "\\?\\", "\\.\\")):
        raise MutationPlanningError(f"device and UNC paths are not allowed: {value}")
    portable = value.replace("\\", "/")
    path = Path(portable)
    if path.is_absolute() or path.drive or any(part in {"", ".", ".."} for part in portable.split("/")):
        raise MutationPlanningError(f"path must be normalized and collection-relative: {value}")
    return path


def _collection_path(root: Path, value: str, *, must_exist: bool) -> Path:
    """Resolve one relative target and reject symlink or lexical escape."""
    root = root.resolve(strict=True)
    relative = _relative_path(value)
    candidate = root.joinpath(relative)
    if must_exist:
        try:
            candidate_metadata = candidate.lstat()
            if candidate.is_symlink() or getattr(candidate_metadata, "st_file_attributes", 0) & 0x400:
                raise MutationPlanningError(f"mutation target is a symlink or reparse point: {value}")
            resolved = candidate.resolve(strict=True)
        except OSError as error:
            raise MutationPlanningError(f"mutation target does not exist: {value}") from error
        if not resolved.is_relative_to(root):
            raise MutationPlanningError(f"path escapes collection: {value}")
        return resolved
    existing_ancestor = candidate.parent
    missing_parts: list[str] = []
    while not existing_ancestor.exists():
        missing_parts.append(existing_ancestor.name)
        parent = existing_ancestor.parent
        if parent == existing_ancestor:
            raise MutationPlanningError(f"path has no collection ancestor: {value}")
        existing_ancestor = parent
    resolved_ancestor = existing_ancestor.resolve(strict=True)
    if not resolved_ancestor.is_relative_to(root):
        raise MutationPlanningError(f"path escapes collection: {value}")
    return resolved_ancestor.joinpath(*reversed(missing_parts), candidate.name)


def _portable(root: Path, path: Path) -> str:
    """Return one normalized collection-relative POSIX path."""
    try:
        return path.relative_to(root).as_posix()
    except ValueError as error:
        raise MutationPlanningError(f"path escapes collection: {path}") from error


def _planned_file(root: Path, path: Path, before: bytes | None, after: bytes | None) -> PlannedFile:
    """Build one deterministic proposed-file value with a non-authoritative diff."""
    relative = _portable(root, path)
    before_text = before.decode("utf-8", errors="replace").splitlines(keepends=True) if before else []
    after_text = after.decode("utf-8", errors="replace").splitlines(keepends=True) if after else []
    diff = "".join(unified_diff(before_text, after_text, fromfile=f"a/{relative}", tofile=f"b/{relative}"))
    return PlannedFile(
        path=relative,
        before_sha256=_digest(before) if before is not None else None,
        after_sha256=_digest(after) if after is not None else None,
        content_base64=b64encode(after).decode("ascii") if after is not None else None,
        diff=diff,
        delete=after is None,
    )


def _manifest(root: Path) -> tuple[CollectionManifest, bytes]:
    """Load the managed collection manifest required for mutation."""
    path = root / "collection.yaml"
    try:
        content = path.read_bytes()
        model = CollectionManifest.model_validate(
            plain_mapping(load_yaml_mapping(content.decode("utf-8"), source=str(path)))
        )
    except (OSError, UnicodeDecodeError, ValidationError, ValueError) as error:
        raise MutationPlanningError("mutation requires a valid collection.yaml") from error
    return model, content


def _optional_digest(path: Path) -> str | None:
    """Return a file digest when the decision input exists."""
    return _digest(path.read_bytes()) if path.is_file() else None


def _snapshot_collection(root: Path, manifest: CollectionManifest) -> str:
    """Digest all local inputs that can change mutation decisions."""
    inspection = inspect_root(root)
    inputs: dict[str, str] = {note.path: note.content_sha256 for note in inspection.notes}
    fixed = ("collection.yaml", "retired-ids.yaml", "profiles.lock.yaml")
    for relative in fixed:
        path = root / relative
        if path.is_file():
            inputs[relative] = _digest(path.read_bytes())
    try:
        semantic = load_semantic_bundle(root, manifest)
    except (ConfigurationError, OSError, ValueError) as error:
        raise MutationPlanningError("semantic bundle is invalid") from error
    inputs.update(semantic.input_digests)
    for reference in (
        manifest.references.catalog,
        manifest.references.trust_policy,
        manifest.references.asset_registry,
        manifest.references.source_registry,
        manifest.references.source_version_registry,
        manifest.references.capture_registry,
        manifest.references.projection_recipe,
    ):
        if reference is None:
            continue
        decision_path = _collection_path(root, reference, must_exist=True)
        inputs[_portable(root, decision_path)] = _digest(decision_path.read_bytes())
    canonical = json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _digest(canonical)


def _canonical_payload(value: object) -> str:
    """Serialize an intent payload deterministically."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _canonical_plan_digest(plan: MutationPlan) -> str:
    """Digest every authoritative serialized plan field except plan digests and diffs."""
    value = plan.model_dump(mode="json")
    value["operation_id"] = ""
    value["plan_sha256"] = ""
    files = cast("list[dict[str, object]]", value["files"])
    for file in files:
        file["diff"] = ""
    return _digest(_canonical_payload(value).encode("utf-8"))


def _plan(
    *,
    intent: MutationIntent,
    actor: str,
    task: str,
    collection: Path,
    manifest: CollectionManifest,
    semantic_unit: str,
    intent_payload: object,
    files: tuple[PlannedFile, ...],
    expected_git_revision: str | None,
    reservations: tuple[IdentityReservation, ...] = (),
    trust_policy: TrustPolicy | None = None,
    trust_grant: TrustGrant | None = None,
    expected_policy_id: str | None = None,
    expected_policy_sha256: str | None = None,
) -> MutationPlan:
    """Finalize a mutation plan and bind every decision input."""
    preconditions = tuple(
        FilePrecondition(path=file.path, exists=file.before_sha256 is not None, sha256=file.before_sha256)
        for file in files
    )
    manifest_path = collection / "collection.yaml"
    lock_path = collection / "profiles.lock.yaml"
    catalog_path = collection / manifest.references.catalog if manifest.references.catalog else None
    policy_path = (
        _collection_path(collection, manifest.references.trust_policy, must_exist=True)
        if manifest.references.trust_policy
        else None
    )
    provisional = MutationPlan(
        operation_id=_ZERO_DIGEST,
        plan_sha256=_ZERO_DIGEST,
        intent=intent,
        actor=actor,
        task=task,
        collection=str(collection),
        collection_id=manifest.collection.id,
        collection_snapshot_sha256=_snapshot_collection(collection, manifest),
        intent_payload_json=_canonical_payload(intent_payload),
        semantic_unit=semantic_unit,
        expected_git_revision=expected_git_revision,
        preconditions=preconditions,
        files=files,
        reservations=reservations,
        configuration_sha256=_digest(manifest_path.read_bytes()),
        profile_lock_sha256=_optional_digest(lock_path),
        catalog_sha256=_optional_digest(catalog_path) if catalog_path else None,
        policy_sha256=_optional_digest(policy_path) if policy_path else None,
        grant_sha256=_digest(_canonical_payload(trust_grant.model_dump(mode="json")).encode("utf-8"))
        if trust_grant
        else None,
    )
    local_policy: TrustPolicy | None = None
    if policy_path is not None:
        try:
            local_policy = TrustPolicy.model_validate(
                plain_mapping(load_yaml_mapping(policy_path.read_text(encoding="utf-8"), source=str(policy_path)))
            )
        except (OSError, ValidationError, ValueError) as error:
            raise MutationPlanningError("collection trust policy is invalid") from error
        if manifest.references.trust_policy_id is None or local_policy.id != manifest.references.trust_policy_id:
            raise MutationPlanningError("collection trust policy identity does not match manifest binding")
    if trust_policy is not None:
        supplied_policy_digest = _digest(_canonical_payload(trust_policy.model_dump(mode="json")).encode("utf-8"))
        if expected_policy_id != trust_policy.id or expected_policy_sha256 != supplied_policy_digest:
            raise MutationPlanningError("external policy identity or digest does not match its expectation")
        if local_policy is not None and local_policy != trust_policy:
            raise MutationPlanningError("supplied policy does not match the collection policy")
        provisional = provisional.model_copy(update={"policy_sha256": supplied_policy_digest})
    digest = _canonical_plan_digest(provisional)
    return provisional.model_copy(update={"operation_id": digest, "plan_sha256": digest})


def _slug(value: str) -> str:
    """Derive a readable lowercase identity from a title or filename."""
    normalized = re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-")
    if not normalized:
        raise MutationPlanningError("cannot derive a non-empty note identity")
    return normalized


def _retired_ids(root: Path) -> frozenset[str]:
    """Load the retired identity set or reject a malformed ledger."""
    path = root / "retired-ids.yaml"
    if not path.exists():
        return frozenset()
    try:
        model = RetiredIdentityFile.model_validate(
            plain_mapping(load_yaml_mapping(path.read_text(encoding="utf-8"), source=str(path)))
        )
    except (OSError, ValidationError, ValueError) as error:
        raise MutationPlanningError("retired identity ledger is invalid") from error
    return frozenset(record.id for record in model.records)


def _profiles_are_locked(root: Path, manifest: CollectionManifest, profiles: tuple[str, ...]) -> None:
    """Require every requested profile to be enabled and integrity-locked."""
    try:
        _ = load_semantic_bundle(root, manifest)
    except (ConfigurationError, OSError, ValueError) as error:
        raise MutationPlanningError("registration requires a valid semantic bundle") from error
    for profile in profiles:
        name, separator, version_text = profile.partition("@")
        if separator != "@" or not version_text.isdigit():
            raise MutationPlanningError(f"invalid profile reference: {profile}")
        version = int(version_text)
        if manifest.profiles.enabled.get(name) != version:
            raise MutationPlanningError(f"profile is not enabled and locked: {profile}")


def _require_clean_markdown(
    content: bytes,
    manifest: CollectionManifest | None = None,
    path: str = "<planned>",
    semantic_bundle: SemanticBundle | None = None,
) -> None:
    """Reject malformed frontmatter and validate any registered envelope."""
    document = parse_markdown(content)
    if document.diagnostics:
        raise MutationPlanningError(document.diagnostics[0][1])
    if document.frontmatter is not None and "id" in document.frontmatter:
        fields = {key: value for key, value in document.frontmatter.items() if key in NoteEnvelope.model_fields}
        try:
            envelope = NoteEnvelope.model_validate(fields)
        except ValidationError as error:
            raise MutationPlanningError("rendered note envelope is invalid") from error
        if manifest is not None:
            note = CollectionNote(
                path=path,
                title=document.headings[0][2] if document.headings else Path(path).stem,
                envelope=envelope,
                body=document.body,
                content_sha256=_digest(content),
                headings=tuple(item[2] for item in document.headings),
                block_ids=tuple(item[1] for item in document.block_ids),
                links=tuple(item[1] for item in document.links),
                properties={str(key): value for key, value in document.frontmatter.items()},
            )
            blocking = tuple(
                finding for finding in validate_profiles(note, manifest) if finding.severity.value == "error"
            )
            if blocking:
                raise MutationPlanningError(blocking[0].message)
            if semantic_bundle is not None:
                semantic_errors = validate_note_semantics(note, manifest, semantic_bundle)
                if semantic_errors:
                    raise MutationPlanningError(semantic_errors[0])


def _included_note(root: Path, manifest: CollectionManifest, path: Path) -> bool:
    """Return whether a Markdown path belongs to a configured note root."""
    for note_root_value in manifest.notes.roots:
        note_root = _collection_path(root, note_root_value, must_exist=True) if note_root_value != "." else root
        if not path.is_relative_to(note_root):
            continue
        relative = path.relative_to(note_root).as_posix()
        collection_relative = _portable(root, path)
        return path_matches(relative, manifest.notes.include) and not path_matches(
            collection_relative, manifest.notes.exclude
        )
    return False


def plan_registration(request: RegistrationRequest) -> MutationPlan:
    """Plan explicit-origin registration of one included unregistered note."""
    root = Path(request.collection).resolve(strict=True)
    manifest, _manifest_bytes = _manifest(root)
    try:
        semantic_bundle = load_semantic_bundle(root, manifest)
    except ConfigurationError as error:
        raise MutationPlanningError("semantic bundle is invalid") from error
    note_path = _collection_path(root, request.note, must_exist=True)
    if note_path.suffix.casefold() != ".md" or not _included_note(root, manifest, note_path):
        raise MutationPlanningError("registration target is not an included Markdown note")
    _profiles_are_locked(root, manifest, request.profiles)
    inspection = inspect_root(root)
    note_matches = [note for note in inspection.notes if note.path == _portable(root, note_path)]
    if len(note_matches) != 1 or note_matches[0].envelope is not None:
        raise MutationPlanningError("registration requires one discovered unregistered note")
    used = {note.envelope.id for note in inspection.notes if note.envelope} | set(_retired_ids(root))
    content = note_path.read_bytes()
    document = parse_markdown(content)
    if document.diagnostics:
        raise MutationPlanningError(document.diagnostics[0][1])
    requested = request.requested_id
    if requested is not None:
        if not _ID.fullmatch(requested) or requested in used:
            raise MutationPlanningError(f"identity is invalid or unavailable: {requested}")
        identity = requested
    else:
        title = document.headings[0][2] if document.headings else note_path.stem
        base = _slug(title)
        identity = base
        suffix = 2
        while identity in used:
            identity = f"{base}-{suffix}"
            suffix += 1
    frontmatter = document.frontmatter or new_yaml_mapping()
    insertion = len(frontmatter)
    values: tuple[tuple[str, object], ...] = (
        ("id", identity),
        ("profiles", list(request.profiles)),
        ("created_by", request.actor),
        ("origin", request.origin.value),
        ("review", new_yaml_mapping({"status": "unreviewed"})),
    )
    for key, value in values:
        if key == "profiles" and not request.profiles:
            continue
        insert_yaml_field(frontmatter, insertion, key, value)
        insertion += 1
    rendered = render_markdown(document, frontmatter)
    _require_clean_markdown(rendered, manifest, _portable(root, note_path), semantic_bundle)
    file = _planned_file(root, note_path, content, rendered)
    return _plan(
        intent=MutationIntent.REGISTER,
        actor=request.actor,
        task=request.task,
        collection=root,
        manifest=manifest,
        semantic_unit=f"register note:{manifest.collection.id}/{identity}",
        intent_payload={
            "note": file.path,
            "identity": identity,
            "profiles": list(request.profiles),
            "origin": request.origin.value,
        },
        files=(file,),
        expected_git_revision=request.expected_git_revision,
        reservations=(
            IdentityReservation(
                namespace="note",
                collection_id=manifest.collection.id,
                identifier=identity,
            ),
        ),
        trust_policy=request.trust_policy,
        trust_grant=request.trust_grant,
        expected_policy_id=request.expected_policy_id,
        expected_policy_sha256=request.expected_policy_sha256,
    )


def _frontmatter_mutation(
    root: Path,
    manifest: CollectionManifest,
    request: MutationRequest,
    path: Path,
    before: bytes,
) -> tuple[PlannedFile, ...]:
    """Plan the bounded tags/aliases metadata mutation surface."""
    if path.suffix.casefold() != ".md" or request.field not in _GENERIC_MUTABLE_FIELDS:
        raise MutationPlanningError("generic metadata mutation is limited to tags and aliases")
    document = parse_markdown(before)
    if document.diagnostics:
        raise MutationPlanningError(document.diagnostics[0][1])
    frontmatter = document.frontmatter or new_yaml_mapping()
    if request.intent is MutationIntent.REMOVE_FIELD:
        if request.field not in frontmatter:
            raise MutationPlanningError(f"frontmatter field does not exist: {request.field}")
        del frontmatter[request.field]
    else:
        if not isinstance(request.value, (list, tuple)):
            raise MutationPlanningError("tags and aliases must be string lists")
        values = cast("list[object] | tuple[object, ...]", request.value)
        if not all(isinstance(item, str) for item in values):
            raise MutationPlanningError("tags and aliases must be string lists")
        frontmatter[request.field] = list(values)
    after = render_markdown(document, frontmatter)
    _require_clean_markdown(after, manifest, _portable(root, path))
    return (_planned_file(root, path, before, after),)


def _retirement_files(
    root: Path,
    manifest: CollectionManifest,
    request: MutationRequest,
    note_path: Path,
) -> tuple[tuple[PlannedFile, ...], str]:
    """Mark an active note retired and append its immutable ledger record."""
    if not isinstance(request.value, RetirementPayload):
        raise MutationPlanningError("retirement requires disposition, retired_on, and optional successor")
    disposition = request.value.disposition
    retired_on = request.value.retired_on.isoformat()
    successor = request.value.successor
    if successor is not None:
        try:
            successor_reference = parse_reference(successor)
        except ValueError as error:
            raise MutationPlanningError("retirement successor is not canonical") from error
        if successor_reference.scheme != "note":
            raise MutationPlanningError("retirement successor must be a canonical note reference")
    before = note_path.read_bytes()
    document = parse_markdown(before)
    if document.frontmatter is None:
        raise MutationPlanningError("retirement target must be a registered note")
    try:
        envelope = NoteEnvelope.model_validate(
            {key: value for key, value in document.frontmatter.items() if key in NoteEnvelope.model_fields}
        )
    except ValidationError as error:
        raise MutationPlanningError("retirement target envelope is invalid") from error
    if envelope.record_status.value != "active":
        raise MutationPlanningError("retirement target is not active")
    document.frontmatter["record_status"] = "retired"
    document.frontmatter["retirement"] = {
        "disposition": disposition,
        "retired_on": retired_on,
        "successor": successor,
    }
    rendered = render_markdown(document, document.frontmatter)
    _require_clean_markdown(rendered, manifest, _portable(root, note_path))
    ledger_path = root / "retired-ids.yaml"
    ledger_before = ledger_path.read_bytes() if ledger_path.exists() else None
    ledger = (
        load_yaml_mapping(ledger_before.decode("utf-8"), source=str(ledger_path))
        if ledger_before
        else new_yaml_mapping({"version": 1, "records": []})
    )
    records = ledger.get("records")
    if not isinstance(records, list):
        raise MutationPlanningError("retired identity ledger is invalid")
    typed_records = cast("list[object]", records)
    if any(
        isinstance(item, dict) and cast("dict[object, object]", item).get("id") == envelope.id for item in typed_records
    ):
        raise MutationPlanningError("identity is already retired")
    typed_records.append(
        {"id": envelope.id, "disposition": disposition, "retired_on": retired_on, "successor": successor}
    )
    return (
        (
            _planned_file(root, note_path, before, rendered),
            _planned_file(root, ledger_path, ledger_before, dump_yaml_mapping(ledger).encode("utf-8")),
        ),
        envelope.id,
    )


def plan_mutation(request: MutationRequest) -> MutationPlan:  # noqa: C901
    """Plan a supported local mutation under the managed collection contract."""
    root = Path(request.collection).resolve(strict=True)
    manifest, _manifest_bytes = _manifest(root)
    if request.intent is MutationIntent.REGISTER:
        if request.path is None or not isinstance(request.value, RegisterMutationPayload):
            raise MutationPlanningError("register requires path and explicit profile/origin payload")
        return plan_registration(
            RegistrationRequest(
                note=request.path,
                collection=str(root),
                actor=request.actor,
                task=request.task,
                origin=request.value.origin,
                profiles=request.value.profiles,
                expected_git_revision=request.expected_git_revision,
                trust_policy=request.trust_policy,
                trust_grant=request.trust_grant,
                expected_policy_id=request.expected_policy_id,
                expected_policy_sha256=request.expected_policy_sha256,
            )
        )
    if request.path is None:
        raise MutationPlanningError(f"{request.intent.value} requires path")
    must_exist = request.intent not in {MutationIntent.CREATE, MutationIntent.RESERVE_COLLECTION}
    path = _collection_path(root, request.path, must_exist=must_exist)
    before = path.read_bytes() if path.exists() else None
    reservations: tuple[IdentityReservation, ...] = ()
    intent_value: object
    if isinstance(request.value, (RegisterMutationPayload, RetirementPayload, CatalogEntry)):
        intent_value = cast("dict[str, object]", request.value.model_dump(mode="json"))
    else:
        intent_value = request.value
    intent_payload: object = {
        "path": request.path,
        "destination": request.destination,
        "field": request.field,
        "value": intent_value,
    }
    if request.intent is MutationIntent.CREATE:
        if before is not None or path.suffix.casefold() != ".md" or not _included_note(root, manifest, path):
            raise MutationPlanningError("create requires a new included Markdown path")
        if not isinstance(request.value, str):
            raise MutationPlanningError("create requires UTF-8 Markdown text")
        after = request.value.encode("utf-8")
        _require_clean_markdown(after, manifest, _portable(root, path))
        files = (_planned_file(root, path, None, after),)
    elif request.intent in {
        MutationIntent.SET_FIELD,
        MutationIntent.REMOVE_FIELD,
        MutationIntent.REPLACE_SUBTREE,
    }:
        if before is None:
            raise MutationPlanningError("metadata mutation target is absent")
        files = _frontmatter_mutation(root, manifest, request, path, before)
    elif request.intent is MutationIntent.MOVE:
        if before is None or request.destination is None:
            raise MutationPlanningError("move requires source and destination")
        destination = _collection_path(root, request.destination, must_exist=False)
        if destination.exists() or not _included_note(root, manifest, destination):
            raise MutationPlanningError("move destination must be a new included Markdown path")
        document = parse_markdown(before)
        if document.frontmatter is None or "id" not in document.frontmatter:
            raise MutationPlanningError("move source must be a registered note")
        _require_clean_markdown(before, manifest, _portable(root, path))
        files = (
            _planned_file(root, destination, None, before),
            _planned_file(root, path, before, None),
        )
    elif request.intent is MutationIntent.RETIRE_IDENTITY:
        files, retired_id = _retirement_files(root, manifest, request, path)
        retirement = cast("RetirementPayload", request.value)
        intent_payload = {
            "path": request.path,
            "retirement": retirement.model_dump(mode="json"),
            "identity": retired_id,
        }
    elif request.intent is MutationIntent.RESERVE_COLLECTION:
        if not isinstance(request.value, CatalogEntry):
            raise MutationPlanningError("reserve_collection requires a catalog entry")
        catalog_before = path.read_bytes() if path.exists() else None
        mapping = (
            load_yaml_mapping(catalog_before.decode("utf-8"), source=str(path))
            if catalog_before
            else new_yaml_mapping({"version": 1, "collections": []})
        )
        entries = mapping.get("collections")
        if not isinstance(entries, list):
            raise MutationPlanningError("catalog collections must be a list")
        cast("list[object]", entries).append(cast("dict[str, object]", request.value.model_dump(mode="json")))
        rendered_catalog = dump_yaml_mapping(mapping).encode("utf-8")
        try:
            catalog = CollectionCatalog.model_validate(plain_mapping(load_yaml_mapping(rendered_catalog.decode())))
        except (ValidationError, ValueError) as error:
            raise MutationPlanningError("catalog reservation is invalid") from error
        reserved = catalog.collections[-1].collection_id
        files = (_planned_file(root, path, catalog_before, rendered_catalog),)
        reservations = (
            IdentityReservation(
                namespace="collection",
                collection_id=manifest.collection.id,
                identifier=reserved,
            ),
        )
    else:
        raise MutationPlanningError(f"unsupported mutation intent: {request.intent.value}")
    return _plan(
        intent=request.intent,
        actor=request.actor,
        task=request.task,
        collection=root,
        manifest=manifest,
        semantic_unit=f"{request.intent.value} {request.path}",
        intent_payload=intent_payload,
        files=files,
        expected_git_revision=request.expected_git_revision,
        reservations=reservations,
        trust_policy=request.trust_policy,
        trust_grant=request.trust_grant,
        expected_policy_id=request.expected_policy_id,
        expected_policy_sha256=request.expected_policy_sha256,
    )


def _git_revision(root: Path) -> str | None:
    """Return the containing repository revision when available."""
    executable = shutil.which("git")
    if executable is None:
        return None
    result = subprocess.run(  # noqa: S603
        [executable, "rev-parse", "HEAD"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def _authorize_apply(
    plan: MutationPlan,
    context: ApplyContext,
    manifest: CollectionManifest,
) -> None:
    """Re-evaluate local and external authorization without conflating authorship."""
    principal = context.principal
    action = plan.intent.value
    if (
        context.trust_policy is not None
        and manifest.references.trust_policy_id is not None
        and context.trust_policy.id != manifest.references.trust_policy_id
    ):
        raise AuthorizationError("trust policy identity does not match the collection binding")
    approval_required = action in manifest.agents.review_required or action in manifest.agents.explicit_authorization
    if approval_required:
        approval = context.approval
        if approval is None or (
            approval.principal != principal.principal
            or approval.operation_id != plan.operation_id
            or approval.plan_sha256 != plan.plan_sha256
            or approval.collection_snapshot_sha256 != plan.collection_snapshot_sha256
            or approval.policy_sha256 != plan.policy_sha256
            or approval.action != action
        ):
            raise AuthorizationError("operation requires a matching in-process owner approval")
    if action in manifest.agents.explicit_authorization:
        if context.trust_grant is None:
            raise AuthorizationError("operation requires an external grant")
        authorize(
            context.trust_grant,
            principal,
            task=plan.task,
            action=action,
            domains=frozenset({manifest.collection.trust_domain}),
            collection=manifest.collection.id,
        )
        return
    if action not in manifest.agents.direct and action not in manifest.agents.review_required:
        raise AuthorizationError("manifest mutation policy denies the operation")
    if not isinstance(principal, LocalFilesystemPrincipal):
        if context.trust_grant is None:
            raise AuthorizationError("non-local operation requires a current grant")
        authorize(
            context.trust_grant,
            principal,
            task=plan.task,
            action=action,
            domains=frozenset({manifest.collection.trust_domain}),
            collection=manifest.collection.id,
        )


def _preflight(  # noqa: C901
    plan: MutationPlan, context: ApplyContext
) -> tuple[Path, dict[str, bytes | None], dict[str, tuple[tuple[str, int, int], ...]]]:
    """Validate the entire hostile serialized plan before any target-derived write."""
    if plan.plan_sha256 != _canonical_plan_digest(plan) or plan.operation_id != plan.plan_sha256:
        raise MutationConflictError("serialized plan digest is invalid")
    if context.expected_operation_id != plan.operation_id:
        raise MutationConflictError("operation identity does not match")
    raw_root = Path(plan.collection)
    root_metadata = raw_root.lstat()
    if raw_root.is_symlink() or getattr(root_metadata, "st_file_attributes", 0) & 0x400:
        raise MutationConflictError("collection root is a symlink or reparse point")
    root = raw_root.resolve(strict=True)
    manifest, _manifest_bytes = _manifest(root)
    if manifest.collection.id != plan.collection_id:
        raise MutationConflictError("collection identity changed after planning")
    try:
        semantic_bundle = load_semantic_bundle(root, manifest)
    except ConfigurationError as error:
        raise MutationConflictError("semantic bundle changed or is invalid") from error
    _authorize_apply(plan, context, manifest)
    if plan.expected_git_revision is not None and _git_revision(root) != plan.expected_git_revision:
        raise MutationConflictError("Git revision changed after planning")
    if _snapshot_collection(root, manifest) != plan.collection_snapshot_sha256:
        raise MutationConflictError("collection decision snapshot changed after planning")
    expected_digests = {
        "configuration": (_optional_digest(root / "collection.yaml"), plan.configuration_sha256),
        "profile lock": (_optional_digest(root / "profiles.lock.yaml"), plan.profile_lock_sha256),
        "catalog": (
            _optional_digest(root / manifest.references.catalog) if manifest.references.catalog else None,
            plan.catalog_sha256,
        ),
    }
    for label, (actual, expected) in expected_digests.items():
        if actual != expected:
            raise MutationConflictError(f"{label} changed after planning")
    context_policy_digest = (
        _digest(_canonical_payload(context.trust_policy.model_dump(mode="json")).encode("utf-8"))
        if context.trust_policy
        else _optional_digest(root / manifest.references.trust_policy)
        if manifest.references.trust_policy
        else None
    )
    context_grant_digest = (
        _digest(_canonical_payload(context.trust_grant.model_dump(mode="json")).encode("utf-8"))
        if context.trust_grant
        else None
    )
    if context_policy_digest != plan.policy_sha256 or context_grant_digest != plan.grant_sha256:
        raise MutationConflictError("authorization inputs changed after planning")
    files_by_path = {file.path: file for file in plan.files}
    conditions_by_path = {item.path: item for item in plan.preconditions}
    if (
        len(files_by_path) != len(plan.files)
        or len(conditions_by_path) != len(plan.preconditions)
        or set(files_by_path) != set(conditions_by_path)
    ):
        raise MutationConflictError("planned files and preconditions are not a unique bijection")
    decoded: dict[str, bytes | None] = {}
    parent_identities: dict[str, tuple[tuple[str, int, int], ...]] = {}
    for relative, file in sorted(files_by_path.items()):
        path = _collection_path(root, relative, must_exist=False)
        parent_identities[relative] = _retained_parent_identities(root, path)
        condition = conditions_by_path[relative]
        if condition.exists != (file.before_sha256 is not None) or condition.sha256 != file.before_sha256:
            raise MutationConflictError("planned before-state is internally inconsistent")
        if path.exists() != condition.exists:
            raise MutationConflictError(f"target existence changed: {relative}")
        if path.exists() and _digest(path.read_bytes()) != condition.sha256:
            raise MutationConflictError(f"target content changed: {relative}")
        if file.delete:
            if file.content_base64 is not None or file.after_sha256 is not None:
                raise MutationConflictError("deletion carries impossible after-state")
            decoded[relative] = None
            continue
        if file.content_base64 is None or file.after_sha256 is None:
            raise MutationConflictError("planned content state is incomplete")
        try:
            content = b64decode(file.content_base64, validate=True)
        except ValueError as error:
            raise MutationConflictError("planned content Base64 is invalid") from error
        if _digest(content) != file.after_sha256:
            raise MutationConflictError("planned content digest is invalid")
        if path.suffix.casefold() == ".md":
            _require_clean_markdown(content, manifest, relative, semantic_bundle)
        decoded[relative] = content
    _revalidate_reservations(root, plan)
    return root, decoded, parent_identities


def _revalidate_reservations(root: Path, plan: MutationPlan) -> None:
    """Rescan active, retired, and catalog identities before writing."""
    inspection = inspect_root(root)
    active = {note.envelope.id for note in inspection.notes if note.envelope}
    retired = set(_retired_ids(root))
    for reservation in plan.reservations:
        if reservation.collection_id != plan.collection_id:
            raise MutationConflictError("reservation collection binding is invalid")
        if reservation.namespace == "note":
            available = reservation.identifier not in active | retired
        else:
            available = True
            for file in plan.files:
                if file.after_sha256 is None or file.content_base64 is None:
                    continue
                try:
                    catalog = CollectionCatalog.model_validate(
                        plain_mapping(load_yaml_mapping(b64decode(file.content_base64).decode("utf-8")))
                    )
                except (UnicodeDecodeError, ValidationError, ValueError):
                    continue
                identifiers = [entry.collection_id for entry in catalog.collections]
                available = identifiers.count(reservation.identifier) == 1
        if available != reservation.expected_available:
            raise MutationConflictError("identity reservation availability changed")


def apply_mutation(plan: MutationPlan, context: ApplyContext) -> ApplyResult:
    """Apply a fully preflighted plan with best-effort multi-file rollback."""
    with _collection_lock(plan, context):
        root, decoded, parent_identities = _preflight(plan, context)
        backups: dict[str, bytes | None] = {}
        for relative in decoded:
            path = _retained_target_path(root, relative, parent_identities)
            backups[relative] = path.read_bytes() if path.exists() else None
        written: list[str] = []
        try:
            for relative, content in decoded.items():
                path = _retained_target_path(root, relative, parent_identities)
                if content is None:
                    path.unlink()
                else:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    _ = _retained_parent_identities(root, path)
                    _atomic_replace(path, content)
                written.append(str(path))
        except Exception as error:
            try:
                _rollback(root, backups, parent_identities)
            except Exception as rollback_error:  # noqa: BLE001
                raise ApplyIndeterminateError(
                    f"apply failed and rollback could not be proved: {rollback_error}"
                ) from error
            raise ApplyIndeterminateError(f"apply failed after writes: {error}") from error
        return ApplyResult(operation_id=plan.operation_id, written_paths=tuple(written))


def _retained_parent_identities(root: Path, target: Path) -> tuple[tuple[str, int, int], ...]:
    """Retain identities of every existing parent and reject reparse components."""
    identities: list[tuple[str, int, int]] = []
    current = root
    for part in target.relative_to(root).parts[:-1]:
        candidate = current / part
        if not candidate.exists():
            break
        metadata = candidate.lstat()
        attributes = getattr(metadata, "st_file_attributes", 0)
        if candidate.is_symlink() or attributes & 0x400 or not candidate.is_dir():
            raise MutationConflictError("mutation parent contains a symlink or reparse component")
        identities.append((candidate.relative_to(root).as_posix(), metadata.st_dev, metadata.st_ino))
        current = candidate
    return tuple(identities)


def _recheck_parent_identities(
    root: Path,
    decoded: Mapping[str, bytes | None],
    retained: Mapping[str, tuple[tuple[str, int, int], ...]],
) -> None:
    """Fail closed when a retained parent identity changes under the lock."""
    for relative in decoded:
        for parent, device, inode in retained[relative]:
            path = root / _relative_path(parent)
            metadata = path.lstat()
            attributes = getattr(metadata, "st_file_attributes", 0)
            if path.is_symlink() or attributes & 0x400 or (metadata.st_dev, metadata.st_ino) != (device, inode):
                raise MutationConflictError("mutation parent identity changed while locked")


def _retained_target_path(
    root: Path,
    relative: str,
    retained: Mapping[str, tuple[tuple[str, int, int], ...]],
) -> Path:
    """Recheck retained parents and return the contained current target path."""
    _recheck_parent_identities(root, {relative: None}, retained)
    lexical = root / _relative_path(relative)
    return _collection_path(root, relative, must_exist=lexical.exists())


def approve_mutation(plan: MutationPlan, principal: AuthenticatedPrincipal) -> MutationApproval:
    """Create an in-memory approval bound to one reviewed plan and principal."""
    return MutationApproval(
        principal=principal.principal,
        operation_id=plan.operation_id,
        plan_sha256=plan.plan_sha256,
        collection_snapshot_sha256=plan.collection_snapshot_sha256,
        policy_sha256=plan.policy_sha256,
        action=plan.intent.value,
        approved_at=datetime.now(timezone.utc),
    )


@contextmanager
def _collection_lock(plan: MutationPlan, context: ApplyContext) -> Generator[None, None, None]:
    """Hold the collection's cross-process lock through preflight and apply."""
    if plan.plan_sha256 != _canonical_plan_digest(plan) or context.expected_operation_id != plan.operation_id:
        raise MutationConflictError("serialized plan identity is invalid")
    raw_root = Path(plan.collection)
    root_metadata = raw_root.lstat()
    if raw_root.is_symlink() or getattr(root_metadata, "st_file_attributes", 0) & 0x400:
        raise MutationConflictError("collection root is a symlink or reparse point")
    root = raw_root.resolve(strict=True)
    state = root / ".knowledge-system"
    if state.exists() and (state.is_symlink() or not state.is_dir()):
        raise MutationConflictError("collection lock directory is unsafe")
    state.mkdir(exist_ok=True)
    lock_path = state / "collection.lock"
    nonce = uuid.uuid4().hex
    record = {
        "pid": os.getpid(),
        "host": _machine_identity(),
        "created": time.time(),
        "nonce": nonce,
    }
    try:
        descriptor = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    except FileExistsError:
        _recover_collection_lock(lock_path, plan, context)
        try:
            descriptor = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        except FileExistsError as error:
            raise MutationConflictError("collection is locked by another process") from error
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            _ = stream.write(json.dumps(record, sort_keys=True))
            stream.flush()
            os.fsync(stream.fileno())
        yield
    finally:
        try:
            current = cast("object", json.loads(lock_path.read_text(encoding="utf-8")))
            if isinstance(current, dict) and cast("dict[object, object]", current).get("nonce") == nonce:
                lock_path.unlink()
        except (OSError, ValueError):
            pass


def _recover_collection_lock(lock_path: Path, plan: MutationPlan, context: ApplyContext) -> None:
    """Recover only a provably dead local lock or an owner-approved unknown lock."""
    recoverable = False
    try:
        record = cast("dict[str, object]", json.loads(lock_path.read_text(encoding="utf-8")))
        machine = _machine_identity()
        same_host = machine is not None and record.get("host") == machine
        created = record.get("created")
        pid = record.get("pid")
        old = isinstance(created, (int, float)) and time.time() - created >= _LOCK_STALE_SECONDS
        recoverable = os.name == "posix" and same_host and old and isinstance(pid, int) and not _process_exists(pid)
    except (OSError, ValueError, TypeError):
        recoverable = False
    approval = context.approval
    approved_recovery = (
        context.recover_lock
        and isinstance(context.principal, LocalFilesystemPrincipal)
        and approval is not None
        and approval.principal == context.principal.principal
        and approval.operation_id == plan.operation_id
        and approval.plan_sha256 == plan.plan_sha256
        and approval.collection_snapshot_sha256 == plan.collection_snapshot_sha256
        and approval.policy_sha256 == plan.policy_sha256
        and approval.action == plan.intent.value
    )
    if not recoverable and not approved_recovery:
        raise MutationConflictError("collection lock ownership cannot be safely recovered")
    lock_path.unlink(missing_ok=False)


def _machine_identity() -> str | None:
    """Return a stable local machine name or None when it cannot be established."""
    candidates = (platform.node().strip(), socket.gethostname().strip())
    return next((value.casefold() for value in candidates if value), None)


def _process_exists(pid: int) -> bool:
    """Return whether the local OS can prove a process remains alive."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except (PermissionError, OSError):
        return True
    return True


def _atomic_replace(path: Path, content: bytes) -> None:
    """Replace one file atomically through a same-directory temporary file."""
    descriptor, temporary_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            _ = stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        _ = temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _rollback(
    root: Path,
    backups: dict[str, bytes | None],
    retained: Mapping[str, tuple[tuple[str, int, int], ...]],
) -> None:
    """Restore all planned paths after a failed multi-file apply."""
    for relative, content in reversed(tuple(backups.items())):
        path = _retained_target_path(root, relative, retained)
        if content is None:
            path.unlink(missing_ok=True)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            _atomic_replace(path, content)
