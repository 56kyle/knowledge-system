# pyright: reportPrivateUsage=false, reportUnusedCallResult=false

from collections.abc import Callable
from datetime import datetime
from datetime import timedelta
from datetime import timezone

import pytest
from pydantic import ValidationError

from knowledge_system.authentication import AuthenticatedPrincipal
from knowledge_system.authentication import authenticate_local_filesystem
from knowledge_system.authentication import issue_authenticated_principal
from knowledge_system.domain import CaptureRecord
from knowledge_system.domain import CollectionIdentity
from knowledge_system.domain import CollectionManifest
from knowledge_system.domain import ProfileSelection
from knowledge_system.domain import ReviewAttestation
from knowledge_system.domain import ReviewStatus
from knowledge_system.domain import SourceVersion
from knowledge_system.domain import TrustGrant
from knowledge_system.exceptions import AuthorizationError


def test_authenticated_principal_rejects_unsealed_construction() -> None:
    with pytest.raises(AuthorizationError):
        AuthenticatedPrincipal(
            "forged",
            datetime.now(timezone.utc),
            "forged",
            _seal=object(),
        )


def test_issue_authenticated_principal_rejects_asserted_mechanism() -> None:
    with pytest.raises(AuthorizationError):
        issue_authenticated_principal(
            principal="agent",
            authenticated_at=datetime.now(timezone.utc),
            mechanism="asserted",
        )


def test_authenticate_local_filesystem_uses_os_identity_not_note_actor() -> None:
    principal = authenticate_local_filesystem()
    assert principal.mechanism == "local-filesystem-os-account"
    assert principal.principal


def test_nested_public_values_are_deeply_immutable() -> None:
    manifest = CollectionManifest(
        collection=CollectionIdentity(id="notes", title="Notes", trust_domain="work"),
        profiles=ProfileSelection(enabled={"research": 1}, settings={"research": {"kinds": ["concept"]}}),
    )
    with pytest.raises(TypeError):
        manifest.profiles.enabled["flap"] = 1  # pyright: ignore[reportIndexIssue]
    assert manifest.profiles.settings["research"]["kinds"] == ("concept",)


@pytest.mark.parametrize(
    "factory",
    [
        lambda: SourceVersion(id="v1", source="source:book", observed_at=datetime(2026, 1, 1)),  # noqa: DTZ001
        lambda: CaptureRecord(
            id="capture",
            content_sha256="0" * 64,
            captured_at=datetime(2026, 1, 1),  # noqa: DTZ001
            captured_by="agent",
        ),
        lambda: ReviewAttestation(
            status=ReviewStatus.REVIEWED,
            reviewed_by="owner",
            reviewed_at=datetime(2026, 1, 1),  # noqa: DTZ001
            basis="sha256:" + "0" * 64,
        ),
        lambda: TrustGrant(
            principal="agent",
            task="task",
            actions=frozenset({"create"}),
            domains=frozenset({"work"}),
            collections=frozenset({"notes"}),
            expires_at=datetime(2026, 1, 1),  # noqa: DTZ001
        ),
    ],
)
def test_time_bearing_models_reject_naive_datetime(factory: Callable[[], object]) -> None:
    with pytest.raises((ValidationError, AuthorizationError)):
        factory()


def test_time_bearing_models_normalize_to_utc() -> None:
    offset = timezone(timedelta(hours=5))
    version = SourceVersion(id="v1", source="source:book", observed_at=datetime(2026, 1, 1, 5, tzinfo=offset))
    assert version.observed_at == datetime(2026, 1, 1, tzinfo=timezone.utc)
