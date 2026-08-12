# pyright: reportPrivateUsage=false

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

import knowledge_system.control as control
from knowledge_system import digest_named_content
from knowledge_system.exceptions import ConfigurationError


if TYPE_CHECKING:
    from knowledge_system.domain import Finding


def test__bundle_digest_is_independent_of_input_order() -> None:
    first = control._bundle_digest({"b.yaml": b"two", "a.yaml": b"one"})
    second = control._bundle_digest({"a.yaml": b"one", "b.yaml": b"two"})
    assert first == second


def test__bundle_digest_binds_logical_path() -> None:
    first = control._bundle_digest({"a.yaml": b"same"})
    second = control._bundle_digest({"b.yaml": b"same"})
    assert first != second


def test__bundle_digest_has_unambiguous_record_boundaries() -> None:
    first = control._bundle_digest({"a": b"b\0c"})
    second = control._bundle_digest({"a\0b": b"c"})
    assert first != second


def test_digest_named_content_is_deterministic_and_record_framed() -> None:
    first = digest_named_content({"a": b"b\0c", "z": b"last"})
    reordered = digest_named_content({"z": b"last", "a": b"b\0c"})
    ambiguous_without_framing = digest_named_content({"a\0b": b"c", "z": b"last"})
    assert first == reordered
    assert first != ambiguous_without_framing


def test__source_revision_with_no_git_repository_uses_distribution_fallback() -> None:
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / "installed" / "knowledge_system" / "source.bin"
        source.parent.mkdir(parents=True)
        _ = source.write_text("", encoding="utf-8")
        assert control._source_revision(source, "1.2.3") == "distribution:1.2.3"


def test__source_revision_with_clean_and_dirty_git_repository(tmp_path: Path) -> None:
    git = shutil.which("git")
    if git is None:
        pytest.skip("Git is unavailable")
    repository = tmp_path / "repository"
    repository.mkdir()
    _ = subprocess.run([git, "init", "--quiet"], cwd=repository, check=True)  # noqa: S603
    _ = subprocess.run([git, "config", "user.email", "test@example.invalid"], cwd=repository, check=True)  # noqa: S603
    _ = subprocess.run([git, "config", "user.name", "Test"], cwd=repository, check=True)  # noqa: S603
    source = repository / "src" / "knowledge_system" / "source.bin"
    source.parent.mkdir(parents=True)
    _ = source.write_text("clean\n", encoding="utf-8")
    _ = subprocess.run([git, "add", "."], cwd=repository, check=True)  # noqa: S603
    _ = subprocess.run([git, "commit", "--quiet", "-m", "test"], cwd=repository, check=True)  # noqa: S603
    head = subprocess.run(  # noqa: S603
        [git, "rev-parse", "HEAD"], cwd=repository, check=True, capture_output=True, text=True
    ).stdout.strip()
    assert control._source_revision(source, "1.2.3") == head
    _ = source.write_text("dirty\n", encoding="utf-8")
    assert control._source_revision(source, "1.2.3") == f"{head}+dirty"


def test__report_duplicates_reports_each_repeated_value_once() -> None:
    findings: list[Finding] = []
    control._report_duplicates(["same", "same", "same"], "duplicate", "item", "items.yaml", findings)
    assert len(findings) == 1


def test__sorted_findings_orders_by_location_then_identity() -> None:
    later = control._invalid_finding("b", "later", "z.yaml")
    earlier = control._invalid_finding("a", "earlier", "a.yaml")
    assert control._sorted_findings([later, earlier]) == (earlier, later)


def test__resolve_root_with_missing_directory(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError):
        _ = control._resolve_root(tmp_path / "missing")
