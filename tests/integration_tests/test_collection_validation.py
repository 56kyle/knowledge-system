# pyright: reportPrivateUsage=false, reportUnusedCallResult=false

from pathlib import Path

import pytest

from knowledge_system import InspectRequest
from knowledge_system import ValidateRequest
from knowledge_system import inspect_collection
from knowledge_system import validate_collection
from knowledge_system.collection import _path_matches
from knowledge_system.validation import _cycle_findings
from knowledge_system.validation import reverse_impact
from tests.helpers import write_manifest
from tests.helpers import write_note


def test_inspect_collection_discovers_root_and_nested_generic_markdown_without_mutation(tmp_path: Path) -> None:
    root_note = tmp_path / "root.md"
    nested_note = tmp_path / "nested" / "note.md"
    write_note(root_note, body="# Root\n\nCafé.\n")
    write_note(nested_note, body="# Nested\n")
    before = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in (root_note, nested_note)}

    report = inspect_collection(InspectRequest(collection=str(tmp_path)))

    assert tuple(note.path for note in report.notes) == ("nested/note.md", "root.md")
    assert report.manifest is None
    assert {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in before} == before


def test__path_matches_treats_double_star_prefix_as_zero_or_more_segments() -> None:
    assert _path_matches("root.md", ("**/*.md",))
    assert _path_matches("nested/root.md", ("**/*.md",))


def test_inspect_collection_reports_strict_manifest_unknown_key(tmp_path: Path) -> None:
    (tmp_path / "collection.yaml").write_text(
        "version: 1\ncollection:\n  id: notes\n  title: Notes\n  trust_domain: work\nunknown: true\n",
        encoding="utf-8",
    )

    report = inspect_collection(InspectRequest(collection=str(tmp_path)))

    assert {finding.code for finding in report.findings} == {"manifest.invalid"}


def test_inspect_collection_rejects_configured_root_escape(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    write_manifest(tmp_path, note_roots=("../" + outside.name,))

    report = inspect_collection(InspectRequest(collection=str(tmp_path)))

    assert "notes.root-invalid" in {finding.code for finding in report.findings}


def test_inspect_collection_rejects_external_note_symlink(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside.md"
    outside.write_text("# Outside\n", encoding="utf-8")
    link = tmp_path / "linked.md"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    report = inspect_collection(InspectRequest(collection=str(tmp_path)))

    assert "note.path-escape" in {finding.code for finding in report.findings}


def test_validate_collection_reports_duplicate_and_retired_identity(tmp_path: Path) -> None:
    write_manifest(tmp_path)
    write_note(tmp_path / "one.md", identity="same")
    write_note(tmp_path / "two.md", identity="same")
    (tmp_path / "retired-ids.yaml").write_text(
        "version: 1\nrecords:\n  - id: same\n    disposition: old\n    retired_on: 2026-08-11\n",
        encoding="utf-8",
    )

    report = validate_collection(ValidateRequest(collection=str(tmp_path)))

    assert {"identity.duplicate", "identity.retired-reused"}.issubset({finding.code for finding in report.findings})


def test_validate_collection_distinguishes_required_and_prospective_missing_relations(tmp_path: Path) -> None:
    write_manifest(tmp_path)
    write_note(
        tmp_path / "source.md",
        identity="source",
        extra=(
            "relations:\n"
            "  - predicate: related\n"
            "    target: note:local-notes/missing-required\n"
            "  - predicate: related\n"
            "    target: note:local-notes/missing-future\n"
            "    resolution: prospective\n"
        ),
    )

    report = validate_collection(ValidateRequest(collection=str(tmp_path)))

    targets = [finding.message for finding in report.findings if finding.code == "relation.target-missing"]
    assert len(targets) == 1
    assert "missing-required" in targets[0]


def test__cycle_findings_reports_one_canonical_finding_for_cycle() -> None:
    findings = _cycle_findings({"a": "b", "b": "c", "c": "a", "tail": "a"})
    assert tuple(finding.code for finding in findings) == ("structure.cycle",)


def test_reverse_impact_returns_transitive_dependents(tmp_path: Path) -> None:
    write_manifest(tmp_path)
    write_note(tmp_path / "target.md", identity="target")
    write_note(
        tmp_path / "middle.md",
        identity="middle",
        extra="relations:\n  - predicate: related\n    target: note:local-notes/target\n",
    )
    write_note(
        tmp_path / "top.md",
        identity="top",
        extra="relations:\n  - predicate: related\n    target: note:local-notes/middle\n",
    )

    affected = reverse_impact("note:local-notes/target#^claim", tmp_path)

    assert affected == ("note:local-notes/middle", "note:local-notes/top")
