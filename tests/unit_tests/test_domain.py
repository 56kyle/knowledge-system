# pyright: reportUnusedCallResult=false

from datetime import date
from datetime import datetime
from datetime import timezone

import pytest
from pydantic import ValidationError

from knowledge_system.domain import CollectionCatalog
from knowledge_system.domain import CollectionIdentity
from knowledge_system.domain import CollectionManifest
from knowledge_system.domain import LiteratureItem
from knowledge_system.domain import MutationIntent
from knowledge_system.domain import MutationRequest
from knowledge_system.domain import NoteEnvelope
from knowledge_system.domain import Origin
from knowledge_system.domain import ProfileDefinition
from knowledge_system.domain import Relation
from knowledge_system.domain import RelationConfidence
from knowledge_system.domain import RetirementPayload
from knowledge_system.domain import ReviewAttestation
from knowledge_system.domain import ReviewStatus


def test_collection_manifest_is_closed_and_frozen() -> None:
    manifest = CollectionManifest(
        collection=CollectionIdentity(id="local-notes", title="Local Notes", trust_domain="work.private")
    )

    with pytest.raises(ValidationError):
        CollectionManifest.model_validate(
            {
                "version": 1,
                "collection": {"id": "local-notes", "title": "Local Notes", "trust_domain": "work"},
                "unknown": True,
            }
        )
    with pytest.raises(ValidationError):
        manifest.collection.title = "Changed"


@pytest.mark.parametrize("profile", ["flap", "flap@", "@1", "flap@latest"])
def test_note_envelope_rejects_unversioned_profiles(profile: str) -> None:
    with pytest.raises(ValidationError):
        NoteEnvelope(id="note", created_by="human", profiles=(profile,))


def test_relation_rejects_inferred_canonical_edge() -> None:
    with pytest.raises(ValidationError):
        Relation(predicate="supports", target="note:local/claim", confidence=RelationConfidence.INFERRED)


def test_review_attestation_requires_complete_review_evidence() -> None:
    with pytest.raises(ValidationError):
        ReviewAttestation(status=ReviewStatus.REVIEWED, reviewed_by="human")

    attestation = ReviewAttestation(
        status=ReviewStatus.REVIEWED,
        reviewed_by="human",
        reviewed_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        basis="sha256:" + "0" * 64,
    )
    assert attestation.status is ReviewStatus.REVIEWED


def test_agent_note_defaults_to_unreviewed() -> None:
    envelope = NoteEnvelope(id="agent-note", created_by="agent", origin=Origin.AGENT)
    assert envelope.review.status is ReviewStatus.UNREVIEWED


def test_collection_catalog_rejects_duplicate_collection_ids() -> None:
    with pytest.raises(ValidationError):
        CollectionCatalog.model_validate(
            {
                "version": 1,
                "collections": [
                    {"collection_id": "same", "manifest": "one/collection.yaml", "trust_domains": ["work"]},
                    {"collection_id": "same", "manifest": "two/collection.yaml", "trust_domains": ["work"]},
                ],
            }
        )


def test_profile_definition_rejects_unknown_invariant_field() -> None:
    with pytest.raises(ValidationError):
        ProfileDefinition.model_validate(
            {
                "version": 1,
                "id": "custom",
                "field_prefix": "custom_",
                "fields": [{"name": "custom_owned", "type": "string"}],
                "invariants": [{"kind": "requires", "fields": ["custom_missing", "custom_owned"]}],
            }
        )


def test_literature_item_rejects_checked_deferral() -> None:
    with pytest.raises(ValidationError):
        LiteratureItem(text="Later", checked=True, outcome="deferred", review_due="2026-09-01")


def test_mutation_request_rejects_payload_for_another_intent() -> None:
    with pytest.raises(ValidationError):
        MutationRequest(
            intent=MutationIntent.CREATE,
            collection="collection",
            actor="actor",
            task="task",
            path="note.md",
            value=RetirementPayload(disposition="old", retired_on=date(2026, 1, 1)),
        )
