# pyright: reportUnusedCallResult=false

from datetime import datetime
from datetime import timezone

import pytest
from pydantic import ValidationError

from knowledge_system.domain import AssetRecord
from knowledge_system.domain import CaptureRecord
from knowledge_system.domain import GraphProjectionEdge
from knowledge_system.domain import IngestionRecord
from knowledge_system.domain import ReviewStatus
from knowledge_system.domain import RevisionAttestation
from knowledge_system.domain import SourceLocator
from knowledge_system.domain import SourceVersion


def test_capture_record_carries_immutable_source_version_and_exact_locator() -> None:
    capture = CaptureRecord(
        id="capture-1",
        content_sha256="0" * 64,
        captured_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        captured_by="agent",
        source_version="source-version:book-v1",
        locator=SourceLocator(
            source="source-version:book-v1",
            kind="quote",
            value="the claim",
            exact_quote="The exact claim.",
            prefix="Before ",
            suffix=" After",
        ),
    )

    assert capture.locator is not None
    assert capture.locator.exact_quote == "The exact claim."


def test_source_version_rejects_non_sha256_digest() -> None:
    with pytest.raises(ValidationError):
        SourceVersion(
            id="source-version-1",
            source="source:book",
            sha256="short",
            observed_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )


def test_source_locator_requires_source_version_reference() -> None:
    with pytest.raises(ValidationError):
        SourceLocator(source="source:mutable", kind="page", value="12")


def test_capture_locator_must_match_capture_source_version() -> None:
    with pytest.raises(ValidationError):
        CaptureRecord(
            id="capture",
            content_sha256="0" * 64,
            captured_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            captured_by="agent",
            source_version="source-version:first",
            locator=SourceLocator(source="source-version:second", kind="page", value="12"),
        )


def test_asset_record_keeps_cache_location_separate_from_canonical_uri() -> None:
    asset = AssetRecord(
        id="diagram",
        uri="https://example.test/diagram.png",
        sha256="0" * 64,
        cached_path="../asset-cache/diagram.png",
    )
    assert asset.uri.startswith("https://")
    assert asset.cached_path == "../asset-cache/diagram.png"


def test_graph_projection_edge_requires_provenance_shape() -> None:
    edge = GraphProjectionEdge(
        source="note:a/one",
        predicate="related",
        target="note:b/two",
        asserted=False,
        provenance=("note:a/one#^claim",),
    )
    assert edge.provenance == ("note:a/one#^claim",)


@pytest.mark.parametrize(("revision", "digest"), [("git:different", "0" * 64), ("git:abc", "1" * 64)])
def test_ingestion_record_rejects_attestation_mismatch(revision: str, digest: str) -> None:
    with pytest.raises(ValidationError):
        IngestionRecord(
            projection="search",
            canonical_reference="note:research/claim",
            revision=revision,
            content_sha256=digest,
            trust_domains=frozenset({"work"}),
            ingested_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            attestation=RevisionAttestation(
                canonical_revision="git:abc",
                content_sha256="0" * 64,
                review_status=ReviewStatus.REVIEWED,
                attested_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            ),
        )
