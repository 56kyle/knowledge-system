# pyright: reportPrivateUsage=false

import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from knowledge_system.exceptions import MutationConflictError
from knowledge_system.exceptions import MutationPlanningError
from knowledge_system.mutation import _CollectionLockRecord
from knowledge_system.mutation import _decode_collection_lock_record
from knowledge_system.mutation import _encode_collection_lock_record
from knowledge_system.mutation import _inspect_collection_lock
from knowledge_system.mutation import _relative_path
from knowledge_system.mutation import _unlink_inspected_collection_lock


_VALID_LOCK_VALUE: dict[str, object] = {
    "created": 1.25,
    "host": "test-machine",
    "nonce": "0123456789abcdef0123456789abcdef",
    "pid": 123,
}
_LOCK_ERROR = "collection lock"


def _lock_content(**changes: object) -> bytes:
    value = {**_VALID_LOCK_VALUE, **changes}
    return json.dumps(value, allow_nan=True).encode()


def _replace_lock_field(
    record: _CollectionLockRecord,
    field: str,
    value: object,
) -> _CollectionLockRecord:
    if field == "pid":
        return replace(record, pid=cast("int", value))
    if field == "created":
        return replace(record, created=cast("float", value))
    if field == "host":
        return replace(record, host=cast("str | None", value))
    if field == "nonce":
        return replace(record, nonce=cast("str", value))
    raise AssertionError(f"unsupported lock-record field: {field}")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("note.md", Path("note.md")),
        ("nested/note.md", Path("nested") / "note.md"),
        (r"nested\note.md", Path("nested") / "note.md"),
        ("nested/topic:detail.md", Path("nested") / "topic:detail.md"),
    ],
)
def test__relative_path_with_valid(value: str, expected: Path) -> None:
    assert _relative_path(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "\x00",
        ".",
        "..",
        "./note.md",
        "nested/../note.md",
        "/absolute.md",
        r"\absolute.md",
        "//server/share.md",
        r"\\server\share.md",
        r"\?\C:\note.md",
        r"\.\C:\note.md",
        "C:/absolute.md",
        "C:drive-relative.md",
        "c:/absolute.md",
        "c:drive-relative.md",
        "nested/C:/absolute.md",
        "nested/C:drive-relative.md",
        r"nested\C:\absolute.md",
        r"nested\C:drive-relative.md",
        "nested//note.md",
        "nested/note.md/",
    ],
)
def test__relative_path_with_invalid(value: str) -> None:
    with pytest.raises(MutationPlanningError):
        _ = _relative_path(value)


def test__encode_collection_lock_record_round_trips(
    collection_lock_record: _CollectionLockRecord,
) -> None:
    encoded = _encode_collection_lock_record(collection_lock_record)

    assert _decode_collection_lock_record(encoded) == collection_lock_record


def test__encode_collection_lock_record_is_deterministic(
    collection_lock_record: _CollectionLockRecord,
) -> None:
    assert _encode_collection_lock_record(collection_lock_record) == (
        b'{"created":1.25,"host":"test-machine","nonce":"0123456789abcdef0123456789abcdef","pid":123}'
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("pid", True),
        ("pid", 0),
        ("pid", -1),
        ("created", True),
        ("created", 1),
        ("created", float("nan")),
        ("created", float("inf")),
        ("created", float("-inf")),
        ("created", -1.0),
        ("host", ""),
        ("host", " test-machine"),
        ("host", "test-machine "),
        ("host", "TEST-MACHINE"),
        ("host", "test\x00machine"),
        ("nonce", "0123456789ABCDEF0123456789ABCDEF"),
        ("nonce", "0" * 31),
        ("nonce", "g" * 32),
    ],
)
def test__collection_lock_record_with_invalid(
    collection_lock_record: _CollectionLockRecord,
    field: str,
    value: object,
) -> None:
    with pytest.raises(ValueError, match=_LOCK_ERROR):
        _ = _replace_lock_field(collection_lock_record, field, value)


@pytest.mark.parametrize(
    "content",
    [
        b"[]",
        b"null",
        json.dumps({key: value for key, value in _VALID_LOCK_VALUE.items() if key != "pid"}).encode(),
        json.dumps({**_VALID_LOCK_VALUE, "extra": True}).encode(),
        _lock_content(pid=True),
        _lock_content(pid=0),
        _lock_content(pid=-1),
        _lock_content(pid=10**1000),
        _lock_content(created=True),
        _lock_content(created=float("nan")),
        _lock_content(created=float("inf")),
        _lock_content(created=float("-inf")),
        _lock_content(created=-1),
        _lock_content(created=10**1000),
        _lock_content(host=""),
        _lock_content(host=" TEST-MACHINE"),
        _lock_content(host="TEST-MACHINE"),
        _lock_content(host=1),
        _lock_content(nonce="0" * 31),
        _lock_content(nonce="F" * 32),
        _lock_content(nonce="g" * 32),
    ],
)
def test__decode_collection_lock_record_with_invalid(content: bytes) -> None:
    with pytest.raises(ValueError, match=_LOCK_ERROR):
        _ = _decode_collection_lock_record(content)


def test__decode_collection_lock_record_normalizes_integer_creation_time() -> None:
    record = _decode_collection_lock_record(_lock_content(created=1))

    assert record.created == 1.0
    assert type(record.created) is float


def test__unlink_inspected_collection_lock_with_unchanged_lock(
    collection_lock_file: Path,
    collection_lock_record: _CollectionLockRecord,
) -> None:
    inspected = _inspect_collection_lock(collection_lock_file)

    _unlink_inspected_collection_lock(
        collection_lock_file,
        inspected,
        expected_nonce=collection_lock_record.nonce,
    )

    assert not collection_lock_file.exists()


def test__unlink_inspected_collection_lock_rejects_replaced_bytes(
    collection_lock_file: Path,
    collection_lock_record: _CollectionLockRecord,
) -> None:
    inspected = _inspect_collection_lock(collection_lock_file)
    replacement = b" " + collection_lock_file.read_bytes()
    _ = collection_lock_file.write_bytes(replacement)

    with pytest.raises(MutationConflictError):
        _unlink_inspected_collection_lock(
            collection_lock_file,
            inspected,
            expected_nonce=collection_lock_record.nonce,
        )

    assert collection_lock_file.read_bytes() == replacement


def test__unlink_inspected_collection_lock_rejects_replaced_identity(
    collection_lock_file: Path,
    collection_lock_record: _CollectionLockRecord,
) -> None:
    inspected = _inspect_collection_lock(collection_lock_file)
    original = collection_lock_file.with_name("original.lock")
    _ = collection_lock_file.replace(original)
    replacement = _encode_collection_lock_record(collection_lock_record)
    _ = collection_lock_file.write_bytes(replacement)

    with pytest.raises(MutationConflictError):
        _unlink_inspected_collection_lock(
            collection_lock_file,
            inspected,
            expected_nonce=collection_lock_record.nonce,
        )

    assert collection_lock_file.read_bytes() == replacement


def test__unlink_inspected_collection_lock_rejects_unexpected_nonce(
    collection_lock_file: Path,
    collection_lock_record: _CollectionLockRecord,
) -> None:
    inspected = _inspect_collection_lock(collection_lock_file)
    unexpected = replace(collection_lock_record, nonce="f" * 32)

    with pytest.raises(MutationConflictError):
        _unlink_inspected_collection_lock(
            collection_lock_file,
            inspected,
            expected_nonce=unexpected.nonce,
        )

    assert collection_lock_file.exists()
