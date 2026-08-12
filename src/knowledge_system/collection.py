"""Collection discovery and parsing for the knowledge_system package."""

from __future__ import annotations

from collections.abc import Mapping  # noqa: TC003
from fnmatch import fnmatchcase
from hashlib import sha256
from pathlib import Path
from pathlib import PurePosixPath

from pydantic import ValidationError

from knowledge_system.codec import load_yaml_mapping
from knowledge_system.codec import parse_markdown
from knowledge_system.codec import plain_mapping
from knowledge_system.domain import CollectionManifest
from knowledge_system.domain import CollectionNote
from knowledge_system.domain import Finding
from knowledge_system.domain import InspectionReport
from knowledge_system.domain import NoteEnvelope
from knowledge_system.domain import Severity
from knowledge_system.exceptions import ConfigurationError


_NOTE_FIELDS: frozenset[str] = frozenset(NoteEnvelope.model_fields)
_GENERIC_EXCLUDES = (
    ".git/**",
    ".venv/**",
    "**/__pycache__/**",
    "build/**",
    "dist/**",
)


def _path_matches(path: str, patterns: tuple[str, ...]) -> bool:
    """Match collection paths with `**/` accepting zero directory segments."""
    return any(
        fnmatchcase(path, pattern) or (pattern.startswith("**/") and fnmatchcase(path, pattern[3:]))
        for pattern in patterns
    )


def path_matches(path: str, patterns: tuple[str, ...]) -> bool:
    """Match a portable collection path against configured glob patterns."""
    return _path_matches(path, patterns)


def _contained_path(root: Path, candidate: Path) -> Path:
    """Resolve a path and reject collection escape, including through symlinks."""
    resolved_root = root.resolve(strict=True)
    resolved_candidate = candidate.resolve(strict=True)
    if not resolved_candidate.is_relative_to(resolved_root):
        raise ConfigurationError(f"path escapes collection: {candidate}")
    return resolved_candidate


def _load_manifest(root: Path, explicit: Path | None) -> tuple[CollectionManifest | None, list[Finding]]:
    """Load collection.yaml when present and return validation findings."""
    manifest_path = explicit or root / "collection.yaml"
    if not manifest_path.exists():
        return None, []
    try:
        manifest_path = _contained_path(root, manifest_path)
        mapping = load_yaml_mapping(manifest_path.read_text(encoding="utf-8"), source=str(manifest_path))
        return CollectionManifest.model_validate(plain_mapping(mapping)), []
    except (OSError, ConfigurationError, ValidationError) as error:
        finding = Finding(
            severity=Severity.ERROR,
            code="manifest.invalid",
            message=str(error),
            path=manifest_path.as_posix(),
        )
        return None, [finding]


def _note_mapping(mapping: Mapping[str, object]) -> dict[str, object]:
    """Select the shared envelope while leaving ordinary/profile properties intact."""
    return {str(key): value for key, value in mapping.items() if str(key) in _NOTE_FIELDS}


def _parse_note(path: Path, root: Path) -> tuple[CollectionNote | None, list[Finding]]:
    """Parse one note into a collection value and diagnostics."""
    relative = path.relative_to(root).as_posix()
    findings: list[Finding] = []
    try:
        content = path.read_bytes()
        document = parse_markdown(content)
    except (OSError, ConfigurationError) as error:
        return None, [Finding(severity=Severity.ERROR, code="note.unreadable", message=str(error), path=relative)]
    findings.extend(
        Finding(
            severity=(Severity.ERROR if "frontmatter" in message.casefold() else Severity.WARNING),
            code="markdown.malformed",
            message=message,
            path=relative,
            line=line,
        )
        for line, message in document.diagnostics
    )
    envelope: NoteEnvelope | None = None
    if document.frontmatter is not None and "id" in document.frontmatter:
        try:
            envelope = NoteEnvelope.model_validate(_note_mapping(document.frontmatter))
        except ValidationError as error:
            findings.append(
                Finding(
                    severity=Severity.ERROR,
                    code="note.envelope-invalid",
                    message=str(error),
                    path=relative,
                    line=1,
                )
            )
    title = document.headings[0][2] if document.headings else path.stem
    note = CollectionNote(
        path=relative,
        title=title,
        envelope=envelope,
        body=document.body,
        content_sha256=sha256(content).hexdigest(),
        headings=tuple(item[2] for item in document.headings),
        block_ids=tuple(item[1] for item in document.block_ids),
        links=tuple(item[1] for item in document.links),
        properties={str(key): value for key, value in (document.frontmatter or {}).items()},
    )
    return note, findings


def inspect_root(  # noqa: C901
    root: Path,
    *,
    manifest_path: Path | None = None,
) -> InspectionReport:
    """Inspect a collection without mutating it."""
    try:
        root = root.resolve(strict=True)
    except OSError as error:
        raise ConfigurationError(f"collection is unavailable: {root}") from error
    if not root.is_dir():
        raise ConfigurationError(f"collection is not a directory: {root}")
    manifest, findings = _load_manifest(root, manifest_path)
    roots = manifest.notes.roots if manifest else (".",)
    include = manifest.notes.include if manifest else ("*.md", "**/*.md")
    exclude = manifest.notes.exclude if manifest else _GENERIC_EXCLUDES
    discovered: dict[str, Path] = {}
    for note_root_value in roots:
        note_root = root / PurePosixPath(note_root_value)
        try:
            note_root = _contained_path(root, note_root)
        except (OSError, ConfigurationError) as error:
            findings.append(
                Finding(
                    severity=Severity.ERROR,
                    code="notes.root-invalid",
                    message=str(error),
                    path=note_root_value,
                )
            )
            continue
        if not note_root.is_dir():
            findings.append(
                Finding(
                    severity=Severity.ERROR,
                    code="notes.root-not-directory",
                    message="configured note root is not a directory",
                    path=note_root_value,
                )
            )
            continue
        for candidate in note_root.rglob("*.md"):
            relative_to_note_root = candidate.relative_to(note_root).as_posix()
            relative_to_collection = candidate.relative_to(root).as_posix()
            if not _path_matches(relative_to_note_root, include) or _path_matches(relative_to_collection, exclude):
                continue
            try:
                resolved = _contained_path(root, candidate)
            except (OSError, ConfigurationError) as error:
                findings.append(
                    Finding(
                        severity=Severity.ERROR,
                        code="note.path-escape",
                        message=str(error),
                        path=relative_to_collection,
                    )
                )
                continue
            discovered[relative_to_collection] = resolved
    notes: list[CollectionNote] = []
    for _relative, path in sorted(discovered.items()):
        note, note_findings = _parse_note(path, root)
        findings.extend(note_findings)
        if note is not None:
            notes.append(note)
    return InspectionReport(
        collection_root=str(root),
        manifest=manifest,
        notes=tuple(notes),
        findings=tuple(sorted(findings, key=lambda item: (item.path or "", item.line or 0, item.code))),
    )
