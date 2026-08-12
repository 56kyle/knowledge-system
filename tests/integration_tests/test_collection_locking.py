# pyright: reportPrivateUsage=false, reportUnusedCallResult=false

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
from knowledge_system.mutation import _CollectionLockRecord
from knowledge_system.mutation import _decode_collection_lock_record
from knowledge_system.mutation import _encode_collection_lock_record
from knowledge_system.mutation import _new_collection_lock_record
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


def _write_lock(root: Path, *, pid: int, created: float) -> Path:
    path = _lock_path(root)
    record = _new_collection_lock_record(pid=pid, created=created)
    path.write_bytes(_encode_collection_lock_record(record))
    return path


def apply_with_windows_os_kill_audit_guard(root: Path) -> None:
    plan = _plan(root)
    lock = _lock_path(root)
    record = _new_collection_lock_record(pid=os.getpid(), created=0)
    lock.write_bytes(_encode_collection_lock_record(record))

    def reject_os_kill(event: str, _arguments: tuple[object, ...]) -> None:
        if event == "os.kill":
            raise RuntimeError("non-POSIX lock recovery attempted to probe a PID")

    sys.addaudithook(reject_os_kill)
    try:
        apply_mutation(plan, _context(plan))
    except MutationConflictError:
        if not (root / "new.md").exists() and lock.exists():
            return
    raise RuntimeError("unapproved Windows lock recovery did not fail closed")


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
        record = _decode_collection_lock_record(lock.read_bytes())
        replacement = replace(record, nonce="f" * 32)
        lock.write_bytes(_encode_collection_lock_record(replacement))
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


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific PID-probe regression")
def test_apply_mutation_does_not_probe_pid_during_unapproved_windows_lock_recovery(
    tmp_path: Path,
) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from pathlib import Path; "
                "from tests.integration_tests.test_collection_locking import "
                "apply_with_windows_os_kill_audit_guard; "
                "apply_with_windows_os_kill_audit_guard(Path(__import__('sys').argv[1]))"
            ),
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize(
    ("pid", "created"),
    [
        (999_999_999, time.time()),
        pytest.param(
            os.getpid(),
            0,
            marks=pytest.mark.skipif(
                sys.platform == "win32",
                reason="os.kill(pid, 0) can interrupt the current Windows console process",
            ),
        ),
    ],
)
def test_fresh_dead_or_stale_live_lock_does_not_recover(tmp_path: Path, pid: int, created: float) -> None:
    plan = _plan(tmp_path)
    _write_lock(tmp_path, pid=pid, created=created)
    with pytest.raises(MutationConflictError):
        apply_mutation(plan, _context(plan))
    assert not (tmp_path / "new.md").exists()


@pytest.mark.parametrize(
    "content",
    [
        b"not-json",
        b"[]",
        (
            b'{"created":0,"host":"test-machine",'
            + b'"nonce":"0123456789abcdef0123456789abcdef","pid":1'
            + (b"0" * 1000)
            + b"}"
        ),
        (
            b'{"created":1'
            + (b"0" * 1000)
            + b',"host":"test-machine",'
            + b'"nonce":"0123456789abcdef0123456789abcdef","pid":1}'
        ),
    ],
)
def test_unknown_lock_requires_explicit_approved_recovery(tmp_path: Path, content: bytes) -> None:
    plan = _plan(tmp_path)
    lock = _lock_path(tmp_path)
    lock.write_bytes(content)
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
    record = _CollectionLockRecord(
        pid=1,
        host="another-host",
        created=0.0,
        nonce="f" * 32,
    )
    lock.write_bytes(_encode_collection_lock_record(record))
    with pytest.raises(MutationConflictError):
        apply_mutation(plan, _context(plan, recover=True))
    apply_mutation(plan, _context(plan, recover=True, approve=True))
    assert (tmp_path / "new.md").exists()


def test_real_second_process_lock_conflicts_then_releases(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    lock = _lock_path(tmp_path)
    script = (
        "import sys; from pathlib import Path; "
        "from knowledge_system.mutation import _encode_collection_lock_record,_new_collection_lock_record; "
        "p=Path(sys.argv[1]); p.write_bytes(_encode_collection_lock_record(_new_collection_lock_record())); "
        "print('ready',flush=True); "
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
