"""Unambiguous deterministic digest helpers for the knowledge_system package."""

from __future__ import annotations

import json
from hashlib import sha256
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from collections.abc import Mapping


def digest_named_content(contents: Mapping[str, bytes]) -> str:
    """Digest sorted logical names and their content digests as canonical JSON records."""
    records = [{"path": path, "sha256": sha256(content).hexdigest()} for path, content in sorted(contents.items())]
    encoded = json.dumps(records, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return sha256(encoded).hexdigest()
