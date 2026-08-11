# pyright: reportUnusedCallResult=false

from pathlib import Path

import pytest

from knowledge_system import ValidateRequest
from knowledge_system import validate_collection
from tests.helpers import write_manifest
from tests.helpers import write_note


def _codes(root: Path) -> set[str]:
    return {finding.code for finding in validate_collection(ValidateRequest(collection=str(root))).findings}


def test_validation_rejects_unknown_unlocked_predicate(tmp_path: Path) -> None:
    write_manifest(tmp_path)
    write_note(
        tmp_path / "note.md",
        identity="note",
        extra="relations:\n  - predicate: invented\n    target: note:local-notes/future\n",
    )
    assert "relation.predicate-unlocked" in _codes(tmp_path)


def test_validation_rejects_prospective_relation_when_predicate_forbids_it(tmp_path: Path) -> None:
    write_manifest(tmp_path)
    write_note(
        tmp_path / "note.md",
        identity="note",
        extra=(
            "relations:\n  - predicate: related\n    target: note:local-notes/future\n    resolution: prospective\n"
        ),
    )
    assert "relation.prospective-forbidden" in _codes(tmp_path)


def test_validation_allows_collection_governed_prospective_predicate(tmp_path: Path) -> None:
    write_manifest(tmp_path)
    manifest = tmp_path / "collection.yaml"
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace(
            "  vocabulary: core@1\n",
            "  vocabulary: core@1\n  prospective_predicates: [related]\n",
        ),
        encoding="utf-8",
    )
    write_note(
        tmp_path / "note.md",
        identity="note",
        extra=(
            "relations:\n  - predicate: related\n    target: note:local-notes/future\n    resolution: prospective\n"
        ),
    )
    codes = _codes(tmp_path)
    assert "relation.target-prospective" in codes
    assert "relation.prospective-forbidden" not in codes


def test_validation_checks_target_block(tmp_path: Path) -> None:
    write_manifest(tmp_path)
    write_note(tmp_path / "target.md", identity="target", body="# Target\nText ^present\n")
    write_note(
        tmp_path / "source.md",
        identity="source",
        extra="relations:\n  - predicate: related\n    target: note:local-notes/target#^missing\n",
    )
    assert "relation.block-missing" in _codes(tmp_path)


def test_validation_rejects_self_and_missing_up(tmp_path: Path) -> None:
    write_manifest(tmp_path)
    write_note(tmp_path / "self.md", identity="self", extra="up: note:local-notes/self\n")
    write_note(tmp_path / "missing.md", identity="missing", extra="up: note:local-notes/absent\n")
    codes = _codes(tmp_path)
    assert "structure.up-self" in codes
    assert "structure.up-missing" in codes


def test_validation_enforces_provenance_reference_schemes(tmp_path: Path) -> None:
    write_manifest(tmp_path)
    write_note(
        tmp_path / "note.md",
        identity="note",
        extra=(
            "sources: [source:mutable]\n"
            "captures: [source-version:not-a-capture]\n"
            "assets: [capture:not-an-asset]\n"
            "source_version: source:mutable\n"
        ),
    )
    codes = _codes(tmp_path)
    assert "provenance.scheme-invalid" in codes
    assert "provenance.source-version-invalid" in codes


def test_validation_resolves_local_note_and_block_provenance(tmp_path: Path) -> None:
    write_manifest(tmp_path)
    write_note(tmp_path / "source.md", identity="source", body="# Source\nEvidence. ^claim\n")
    write_note(
        tmp_path / "claim.md",
        identity="claim",
        extra="sources: [note:local-notes/source#^claim]\n",
    )
    assert "provenance.local-reference-missing" not in _codes(tmp_path)


@pytest.mark.parametrize("reference", ["note:local-notes/missing", "note:local-notes/source#^missing"])
def test_validation_rejects_missing_local_note_or_block_provenance(tmp_path: Path, reference: str) -> None:
    write_manifest(tmp_path)
    write_note(tmp_path / "source.md", identity="source", body="# Source\nEvidence. ^claim\n")
    write_note(tmp_path / "claim.md", identity="claim", extra=f"sources: [{reference}]\n")
    assert "provenance.local-reference-missing" in _codes(tmp_path)


def test_validation_composes_flap_and_research_profiles(tmp_path: Path) -> None:
    write_manifest(tmp_path, enabled_profiles={"flap": 1, "research": 1})
    write_note(
        tmp_path / "claim.md",
        identity="claim",
        extra=(
            "profiles: [flap@1, research@1]\n"
            "flap_type: atomic\n"
            "research_kind: concept\n"
            "research_depth: named\n"
            "sources: [source-version:book-v1]\n"
        ),
    )
    assert not validate_collection(ValidateRequest(collection=str(tmp_path))).has_blocking_findings
