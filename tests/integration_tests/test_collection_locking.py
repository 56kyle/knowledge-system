# pyright: reportPrivateUsage=false, reportUnusedCallResult=false

import json
import os
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from typing import TextIO
from typing import cast

import pytest

from knowledge_system.authentication import authenticate_local_filesystem
from knowledge_system.domain import ApplyContext
from knowledge_system.domain import MutationIntent
from knowledge_system.domain import MutationPlan
from knowledge_system.domain import MutationRequest
from knowledge_system.exceptions import MutationConflictError
from knowledge_system.mutation import _collection_lock
from knowledge_system.mutation import apply_mutation
from knowledge_system.mutation import approve_mutation
from knowledge_system.mutation import plan_mutation
from tests.helpers import write_manifest


def _plan(root: Path) -> MutationPlan:
    write_manifest(root)
    return plan_mutation(
        MutationRequest(
            intent=MutationIntent.CREATE,
            collection=str(root),
            actor="author",
            task="task",
            path="new.md",
            value="# New\n",
        )
    )


def _context(plan: MutationPlan, *, recover: bool = False, approve: bool = False) -> ApplyContext:
    principal = authenticate_local_filesystem()
    return ApplyContext(
        principal=principal,
        expected_operation_id=plan.operation_id,
        recover_lock=recover,
        approval=approve_mutation(plan, principal) if approve else None,
    )


def _lock_path(root: Path) -> Path:
    path = root / ".knowledge-system" / "collection.lock"
    path.parent.mkdir(exist_ok=True)
    return path


def _write_lock(root: Path, *, pid: int, created: float, nonce: str = "nonce") -> Path:
    path = _lock_path(root)
    path.write_text(
        json.dumps(
            {
                "pid": pid,
                "host": os.environ.get("COMPUTERNAME", "unknown"),
                "created": created,
                "nonce": nonce,
            }
        ),
        encoding="utf-8",
    )
    return path


def test_collection_lock_releases_after_context(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    lock = _lock_path(tmp_path)
    with _collection_lock(plan, _context(plan)):
        assert lock.exists()
    assert not lock.exists()


def test_collection_lock_nonce_change_prevents_unowned_cleanup(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    lock = _lock_path(tmp_path)
    with _collection_lock(plan, _context(plan)):
        record = cast("dict[str, object]", json.loads(lock.read_text(encoding="utf-8")))
        record["nonce"] = "different-owner"
        lock.write_text(json.dumps(record), encoding="utf-8")
    assert lock.exists()


@pytest.mark.skipif(sys.platform == "win32", reason="Windows cannot prove dead PIDs with os.kill(pid, 0)")
def test_stale_dead_local_lock_recovers_automatically(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    completed = subprocess.Popen([sys.executable, "-c", "pass"])
    assert completed.wait(timeout=10) == 0
    _write_lock(tmp_path, pid=completed.pid, created=0)
    apply_mutation(plan, _context(plan))
    assert (tmp_path / "new.md").exists()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific fail-closed recovery contract")
def test_stale_dead_local_lock_on_windows_requires_approved_recovery(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    completed = subprocess.Popen([sys.executable, "-c", "pass"])
    assert completed.wait(timeout=10) == 0
    _write_lock(tmp_path, pid=completed.pid, created=0)
    with pytest.raises(MutationConflictError):
        apply_mutation(plan, _context(plan))
    apply_mutation(plan, _context(plan, recover=True, approve=True))
    assert (tmp_path / "new.md").exists()


@pytest.mark.parametrize(
    ("pid", "created"),
    [(999_999_999, time.time()), (os.getpid(), 0)],
)
def test_fresh_dead_or_stale_live_lock_does_not_recover(tmp_path: Path, pid: int, created: float) -> None:
    plan = _plan(tmp_path)
    _write_lock(tmp_path, pid=pid, created=created)
    with pytest.raises(MutationConflictError):
        apply_mutation(plan, _context(plan))
    assert not (tmp_path / "new.md").exists()


def test_unknown_lock_requires_explicit_approved_recovery(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    lock = _lock_path(tmp_path)
    lock.write_text("not-json", encoding="utf-8")
    with pytest.raises(MutationConflictError):
        apply_mutation(plan, _context(plan))
    apply_mutation(plan, _context(plan, recover=True, approve=True))
    assert (tmp_path / "new.md").exists()


@pytest.mark.parametrize(
    ("binding", "invalid_value"),
    [
        ("principal", "another-principal"),
        ("operation_id", "invalid-operation"),
        ("plan_sha256", "invalid-plan"),
        ("collection_snapshot_sha256", "invalid-snapshot"),
        ("policy_sha256", "invalid-policy"),
        ("action", "invalid-action"),
    ],
)
def test_stale_lock_recovery_rejects_mismatched_approval_before_removal(
    tmp_path: Path,
    binding: str,
    invalid_value: str,
) -> None:
    plan = _plan(tmp_path)
    lock = _lock_path(tmp_path)
    lock.write_text("not-json", encoding="utf-8")
    principal = authenticate_local_filesystem()
    approval = approve_mutation(plan, principal)
    invalid = replace(approval, **{binding: invalid_value})
    context = ApplyContext(
        principal=principal,
        expected_operation_id=plan.operation_id,
        approval=invalid,
        recover_lock=True,
    )
    with pytest.raises(MutationConflictError):
        apply_mutation(plan, context)
    assert lock.read_text(encoding="utf-8") == "not-json"


def test_unknown_host_lock_requires_complete_owner_approval(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    lock = _lock_path(tmp_path)
    lock.write_text(
        json.dumps({"pid": 1, "host": "another-host", "created": 0, "nonce": "foreign"}),
        encoding="utf-8",
    )
    with pytest.raises(MutationConflictError):
        apply_mutation(plan, _context(plan, recover=True))
    apply_mutation(plan, _context(plan, recover=True, approve=True))
    assert (tmp_path / "new.md").exists()


def test_real_second_process_lock_conflicts_then_releases(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    lock = _lock_path(tmp_path)
    script = (
        "import json,os,sys,time; from pathlib import Path; "
        "p=Path(sys.argv[1]); p.write_text(json.dumps({'pid':os.getpid(),'host':os.environ.get('COMPUTERNAME','unknown'),"
        "'created':time.time(),'nonce':'holder'}),encoding='utf-8'); print('ready',flush=True); "
        "sys.stdin.readline(); p.unlink()"
    )
    process: subprocess.Popen[str] = subprocess.Popen(
        [sys.executable, "-c", script, str(lock)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    try:
        assert process.stdout is not None
        stdout = cast("TextIO", process.stdout)
        assert stdout.readline().strip() == "ready"
        with pytest.raises(MutationConflictError):
            apply_mutation(plan, _context(plan))
        assert process.stdin is not None
        _ = process.stdin.write("release\n")
        process.stdin.flush()
        assert process.wait(timeout=10) == 0
        apply_mutation(plan, _context(plan))
        assert (tmp_path / "new.md").exists()
    finally:
        if process.poll() is None:
            process.kill()
            _ = process.wait(timeout=10)
