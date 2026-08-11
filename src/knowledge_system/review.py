"""Revision-scoped review digests for knowledge_system."""

from __future__ import annotations

from hashlib import sha256

from knowledge_system.codec import dump_yaml_mapping
from knowledge_system.codec import new_yaml_mapping
from knowledge_system.codec import parse_markdown
from knowledge_system.domain import ReviewBasis


def compute_review_basis(markdown: bytes) -> ReviewBasis:
    """Digest normalized Markdown after removing review attestation metadata."""
    document = parse_markdown(markdown)
    if document.frontmatter is None:
        normalized = document.text.replace("\r\n", "\n").encode("utf-8")
    else:
        metadata = new_yaml_mapping(dict(document.frontmatter))
        _ = metadata.pop("review", None)
        for legacy in ("review_status", "reviewed_by", "reviewed_at", "review_basis"):
            _ = metadata.pop(legacy, None)
        rendered_metadata = dump_yaml_mapping(metadata)
        normalized_body = document.body.replace("\r\n", "\n")
        normalized_text = f"---\n{rendered_metadata}---\n{normalized_body}"
        normalized = normalized_text.encode("utf-8")
        if document.bom:
            normalized = b"\xef\xbb\xbf" + normalized
    return ReviewBasis(digest=sha256(normalized).hexdigest())
