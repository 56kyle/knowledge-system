"""Authoritative semantic profile and vocabulary loading."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING
from typing import cast

from pydantic import ValidationError

from knowledge_system.codec import load_yaml_mapping
from knowledge_system.codec import plain_mapping
from knowledge_system.domain import CollectionManifest
from knowledge_system.domain import CollectionNote
from knowledge_system.domain import PredicateDefinition
from knowledge_system.domain import ProfileDefinition
from knowledge_system.domain import ProfileLock
from knowledge_system.domain import ProfileLockFile
from knowledge_system.exceptions import ConfigurationError
from knowledge_system.profiles import BUILTIN_LOCK_DIGESTS
from knowledge_system.profiles import BUILTIN_PREDICATES


if TYPE_CHECKING:
    from collections.abc import Mapping


@dataclass(frozen=True, slots=True)
class SemanticBundle:
    """Integrity-verified semantics selected by one collection manifest."""

    profiles: Mapping[str, ProfileDefinition]
    predicates: Mapping[str, PredicateDefinition]
    input_digests: Mapping[str, str]
    lock_sha256: str


def load_semantic_bundle(root: Path, manifest: CollectionManifest) -> SemanticBundle:  # noqa: C901
    """Load the one authoritative enabled-profile and selected-vocabulary bundle."""
    collection_root = root.resolve(strict=True)
    lock_path = collection_root / "profiles.lock.yaml"
    try:
        lock_bytes = lock_path.read_bytes()
        locks = ProfileLockFile.model_validate(
            plain_mapping(load_yaml_mapping(lock_bytes.decode("utf-8"), source=str(lock_path)))
        )
    except (OSError, UnicodeDecodeError, ValidationError, ValueError) as error:
        raise ConfigurationError("semantic bundle requires valid profiles.lock.yaml") from error
    selected_profiles = {(name, version) for name, version in manifest.profiles.enabled.items()}
    profile_locks = _exact_locks(locks.profiles, selected_profiles, "profile")
    vocabulary_key = (manifest.relations.vocabulary, 1)
    vocabulary_locks = _exact_locks(locks.relation_vocabularies, {vocabulary_key}, "relation vocabulary")
    definitions: dict[str, ProfileDefinition] = {}
    predicates: dict[str, PredicateDefinition] = {}
    inputs = {"profiles.lock.yaml": sha256(lock_bytes).hexdigest()}
    for lock in (*profile_locks, *vocabulary_locks):
        expected = BUILTIN_LOCK_DIGESTS.get((lock.identifier, lock.version))
        if expected is not None:
            if lock.sha256 != expected or lock.path is not None:
                raise ConfigurationError(f"built-in semantic lock mismatch: {lock.identifier}@{lock.version}")
            if lock in vocabulary_locks:
                overlap = set(predicates).intersection(BUILTIN_PREDICATES)
                if overlap:
                    raise ConfigurationError(f"duplicate predicate ownership: {sorted(overlap)[0]}")
                predicates.update({name: PredicateDefinition(name=name) for name in BUILTIN_PREDICATES})
            continue
        definition, relative, digest = _load_definition(collection_root, lock)
        inputs[relative] = digest
        key = f"{definition.id}@{definition.version}"
        if lock in profile_locks:
            definitions[key] = definition
            for predicate in definition.predicates:
                if predicate.name in predicates:
                    raise ConfigurationError(f"duplicate predicate ownership: {predicate.name}")
                predicates[predicate.name] = predicate
        else:
            for predicate in definition.predicates:
                if predicate.name in predicates:
                    raise ConfigurationError(f"duplicate predicate ownership: {predicate.name}")
                predicates[predicate.name] = predicate
    owners: dict[str, str] = {}
    for key, definition in definitions.items():
        for field in definition.fields:
            previous = owners.setdefault(field.name, key)
            if previous != key:
                raise ConfigurationError(f"duplicate custom field ownership: {field.name}")
    return SemanticBundle(
        profiles=MappingProxyType(definitions),
        predicates=MappingProxyType(predicates),
        input_digests=MappingProxyType(inputs),
        lock_sha256=sha256(lock_bytes).hexdigest(),
    )


def validate_note_semantics(  # noqa: C901
    note: CollectionNote, manifest: CollectionManifest, bundle: SemanticBundle
) -> tuple[str, ...]:
    """Validate one rendered note against the already loaded semantic bundle."""
    if note.envelope is None:
        return ()
    errors: list[str] = []
    enabled = {f"{name}@{version}" for name, version in manifest.profiles.enabled.items()}
    for selected in note.envelope.profiles:
        if selected not in enabled:
            errors.append(f"profile is not enabled: {selected}")
    for relation in note.envelope.relations:
        if relation.predicate not in bundle.predicates:
            errors.append(f"predicate is not selected: {relation.predicate}")
    for selected in note.envelope.profiles:
        definition = bundle.profiles.get(selected)
        if definition is None:
            continue
        present = {field.name for field in definition.fields if field.name in note.properties}
        for field in definition.fields:
            if field.required and field.name not in present:
                errors.append(f"profile {selected} requires {field.name}")
            if field.name in present and not _custom_field_matches(note.properties[field.name], field.type, field.enum):
                errors.append(f"profile {selected} field {field.name} is invalid")
        for invariant in definition.invariants:
            fields = set(invariant.fields)
            selected_fields = fields & present
            valid = (
                (invariant.kind == "required_together" and (not selected_fields or selected_fields == fields))
                or (invariant.kind == "exactly_one" and len(selected_fields) == 1)
                or (
                    invariant.kind == "requires"
                    and (invariant.fields[0] not in present or set(invariant.fields[1:]).issubset(present))
                )
            )
            if not valid:
                errors.append(f"profile {selected} invariant {invariant.kind} failed")
    return tuple(errors)


def _custom_field_matches(value: object, kind: str, enum: tuple[str, ...]) -> bool:
    """Validate one declarative field without coercing authored YAML."""
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


def _exact_locks(
    locks: tuple[ProfileLock, ...],
    selected: set[tuple[str, int]],
    label: str,
) -> tuple[ProfileLock, ...]:
    """Require exactly one lock for every selected identity and no extra locks."""
    keys = [(lock.identifier, lock.version) for lock in locks]
    if set(keys) != selected or len(keys) != len(set(keys)):
        raise ConfigurationError(f"{label} locks must exactly match selected semantics")
    return locks


def _load_definition(root: Path, lock: ProfileLock) -> tuple[ProfileDefinition, str, str]:
    """Load one contained custom definition and verify raw bytes and identity."""
    if lock.path is None:
        raise ConfigurationError(f"custom semantic lock requires a path: {lock.identifier}")
    relative = Path(lock.path)
    if relative.is_absolute() or ".." in relative.parts:
        raise ConfigurationError("semantic definition path escapes collection")
    try:
        path = (root / relative).resolve(strict=True)
        if not path.is_relative_to(root) or path.is_symlink():
            raise ConfigurationError("semantic definition path escapes collection")
        content = path.read_bytes()
        digest = sha256(content).hexdigest()
        if digest != lock.sha256:
            raise ConfigurationError("semantic definition digest mismatch")
        definition = ProfileDefinition.model_validate(
            plain_mapping(load_yaml_mapping(content.decode("utf-8"), source=str(path)))
        )
    except (OSError, UnicodeDecodeError, ValidationError, ValueError) as error:
        raise ConfigurationError(f"invalid semantic definition: {lock.path}") from error
    if definition.id != lock.identifier or definition.version != lock.version:
        raise ConfigurationError("semantic definition identity/version mismatch")
    return definition, relative.as_posix(), digest
