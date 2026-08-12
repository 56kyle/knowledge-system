# pyright: reportUnusedCallResult=false

import json
import subprocess
import sys
from pathlib import Path

import pytest

from knowledge_system.domain import MutationIntent
from knowledge_system.domain import MutationRequest
from tests.helpers import write_manifest


def _run(*arguments: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "knowledge_system", *arguments],
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def test_cli_help_succeeds_in_real_process() -> None:
    result = _run("--help")
    assert result.returncode == 0
    assert "Inspect, validate, and safely mutate" in result.stdout


def test_cli_inspect_json_is_schema_versioned_and_deterministic(tmp_path: Path) -> None:
    (tmp_path / "note.md").write_text("# Café\n", encoding="utf-8")

    first = _run("inspect", str(tmp_path), "--format", "json")
    second = _run("inspect", str(tmp_path), "--format", "json")

    assert first.returncode == 0
    assert first.stdout == second.stdout
    assert json.loads(first.stdout)["schema_version"] == 1


def test_cli_validate_returns_one_for_blocking_findings(tmp_path: Path) -> None:
    (tmp_path / "collection.yaml").write_text(
        "version: 1\ncollection:\n  id: BAD\n  title: Bad\n  trust_domain: work\n",
        encoding="utf-8",
    )
    result = _run("validate", str(tmp_path))
    assert result.returncode == 1
    assert "manifest.invalid" in result.stdout


def test_cli_invocation_error_returns_two() -> None:
    result = _run("register")
    assert result.returncode == 2


def test_cli_mutation_conflict_returns_three_without_overwriting(tmp_path: Path) -> None:
    write_manifest(tmp_path)
    request_path = tmp_path / "request.json"
    plan_path = tmp_path / "plan.json"
    target = tmp_path / "new.md"
    request = MutationRequest(
        intent=MutationIntent.CREATE,
        collection=str(tmp_path),
        actor="agent",
        task="task-1",
        path="new.md",
        value="# Planned\n",
    )
    request_path.write_text(request.model_dump_json(), encoding="utf-8")
    planned = _run("mutation", "plan", str(request_path), "--out", str(plan_path))
    assert planned.returncode == 0
    target.write_text("# Human\n", encoding="utf-8")

    result = _run("mutation", "apply", str(plan_path))

    assert result.returncode == 3
    assert target.read_text(encoding="utf-8") == "# Human\n"


def _write_create_request(root: Path, *, target: str = "new.md") -> Path:
    write_manifest(root)
    request_path = root / "request.json"
    request = MutationRequest(
        intent=MutationIntent.CREATE,
        collection=str(root),
        actor="agent",
        task="task-1",
        path=target,
        value="# Planned\n",
    )
    request_path.write_text(request.model_dump_json(), encoding="utf-8")
    return request_path


def test_cli_mutation_plan_stdout_is_the_complete_plan(tmp_path: Path) -> None:
    request = _write_create_request(tmp_path)
    result = _run("mutation", "plan", str(request), "--stdout")
    assert json.loads(result.stdout)["intent"] == "create"


def test_cli_register_stdout_is_json_only_and_diff_uses_stderr(tmp_path: Path) -> None:
    write_manifest(tmp_path)
    note = tmp_path / "capture.md"
    note.write_text("# Capture\n", encoding="utf-8")
    result = _run(
        "register",
        str(note),
        "--collection",
        str(tmp_path),
        "--actor",
        "agent",
        "--task",
        "capture",
        "--stdout",
    )
    assert json.loads(result.stdout)["intent"] == "register"
    assert "+++" in result.stderr


@pytest.mark.parametrize("arguments", [(), ("--out", "plan.json", "--stdout")])
def test_cli_mutation_plan_requires_exactly_one_output(
    tmp_path: Path,
    arguments: tuple[str, ...],
) -> None:
    request = _write_create_request(tmp_path)
    result = _run("mutation", "plan", str(request), *arguments, cwd=tmp_path)
    assert result.returncode == 2


def test_cli_mutation_plan_does_not_replace_existing_output(tmp_path: Path) -> None:
    request = _write_create_request(tmp_path)
    output = tmp_path / "plan.json"
    output.write_bytes(b"human bytes\n")
    result = _run("mutation", "plan", str(request), "--out", str(output))
    assert (result.returncode, output.read_bytes()) == (2, b"human bytes\n")


def test_cli_mutation_plan_rejects_symlink_output(tmp_path: Path) -> None:
    request = _write_create_request(tmp_path)
    target = tmp_path / "human.json"
    target.write_bytes(b"human bytes\n")
    output = tmp_path / "plan.json"
    try:
        output.symlink_to(target)
    except OSError:
        pytest.skip("file symlink creation is unavailable")
    result = _run("mutation", "plan", str(request), "--out", str(output))
    assert (result.returncode, target.read_bytes()) == (2, b"human bytes\n")


def test_cli_mutation_plan_rejects_output_that_is_a_mutation_target(tmp_path: Path) -> None:
    output = tmp_path / "plan.json"
    request = _write_create_request(tmp_path, target=output.name)
    result = _run("mutation", "plan", str(request), "--out", str(output))
    assert (result.returncode, output.exists()) == (2, False)


def test_cli_schema_export_then_check_is_clean(tmp_path: Path) -> None:
    exported = _run("schema", "export", "--destination", str(tmp_path))
    checked = _run("schema", "export", "--destination", str(tmp_path), "--check")
    assert exported.returncode == 0
    assert checked.returncode == 0
    assert "schemas: 0 checked" in checked.stdout


@pytest.mark.skipif(sys.platform != "win32", reason="uses Windows delete-sharing as a real filesystem fault")
def test_cli_apply_returns_four_when_rollback_cannot_be_proved(tmp_path: Path) -> None:
    write_manifest(tmp_path)
    source = tmp_path / "source.md"
    destination = tmp_path / "destination.md"
    source.write_text("---\nid: source\ncreated_by: human\n---\n# Source\n", encoding="utf-8")
    request = MutationRequest(
        intent=MutationIntent.MOVE,
        collection=str(tmp_path),
        actor="author",
        task="task-1",
        path="source.md",
        destination="destination.md",
    )
    request_path = tmp_path / "move.json"
    plan_path = tmp_path / "move-plan.json"
    request_path.write_text(request.model_dump_json(), encoding="utf-8")
    assert _run("mutation", "plan", str(request_path), "--out", str(plan_path)).returncode == 0

    with source.open("rb"):
        result = _run("mutation", "apply", str(plan_path))

    assert result.returncode == 4
    assert source.exists()
    assert destination.exists()
