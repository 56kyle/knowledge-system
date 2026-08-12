"""Fixtures used in unit tests."""

# pyright: reportPrivateUsage=false

from pathlib import Path

import pytest

from knowledge_system.mutation import _CollectionLockRecord
from knowledge_system.mutation import _encode_collection_lock_record


@pytest.fixture
def collection_lock_record() -> _CollectionLockRecord:
    return _CollectionLockRecord(
        pid=123,
        host="test-machine",
        created=1.25,
        nonce="0123456789abcdef0123456789abcdef",
    )


@pytest.fixture
def collection_lock_file(
    tmp_path: Path,
    collection_lock_record: _CollectionLockRecord,
) -> Path:
    path = tmp_path / "collection.lock"
    _ = path.write_bytes(_encode_collection_lock_record(collection_lock_record))
    return path
