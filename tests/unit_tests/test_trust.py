from datetime import datetime
from datetime import timedelta
from datetime import timezone

import pytest

from knowledge_system.authentication import issue_authenticated_principal
from knowledge_system.domain import CrossDomainRule
from knowledge_system.domain import KnowledgeEdge
from knowledge_system.domain import KnowledgeSnapshot
from knowledge_system.domain import TrustGrant
from knowledge_system.domain import TrustPolicy
from knowledge_system.exceptions import AuthorizationError
from knowledge_system.trust import authorize
from knowledge_system.trust import compute_effective_domains
from knowledge_system.trust import relation_is_allowed
from knowledge_system.trust import select_exact_domain_enclave


def test_compute_effective_domains_propagates_transitively_toward_sources() -> None:
    snapshot = KnowledgeSnapshot(
        node_domains={"a": frozenset({"public"}), "b": frozenset({"work"}), "c": frozenset({"private"})},
        edges=(
            KnowledgeEdge(source="a", target="b", predicate="derived_from"),
            KnowledgeEdge(source="b", target="c", predicate="derived_from"),
        ),
    )

    analysis = compute_effective_domains(snapshot)

    assert analysis.effective_domains["a"] == frozenset({"public", "work", "private"})
    assert analysis.effective_domains["b"] == frozenset({"work", "private"})


def test_select_exact_domain_enclave_excludes_domain_supersets() -> None:
    analysis = compute_effective_domains(
        KnowledgeSnapshot(node_domains={"exact": frozenset({"work"}), "mixed": frozenset({"work", "private"})})
    )
    assert select_exact_domain_enclave(analysis, frozenset({"work"})) == ("exact",)


def test_relation_is_allowed_requires_explicit_cross_domain_rule() -> None:
    policy = TrustPolicy(
        id="trust-v1",
        rules=(
            CrossDomainRule(
                source_domains=frozenset({"work"}),
                destination_domains=frozenset({"public"}),
                predicates=frozenset({"supports"}),
            ),
        ),
    )

    assert relation_is_allowed(
        policy,
        source_domains=frozenset({"work"}),
        destination_domains=frozenset({"public"}),
        predicate="supports",
    )
    assert not relation_is_allowed(
        policy,
        source_domains=frozenset({"work"}),
        destination_domains=frozenset({"public"}),
        predicate="contradicts",
    )


def test_authorize_accepts_matching_unexpired_grant() -> None:
    now = datetime.now(timezone.utc)
    grant = TrustGrant(
        principal="agent",
        task="task-1",
        actions=frozenset({"inspect"}),
        domains=frozenset({"work"}),
        collections=frozenset({"notes"}),
        expires_at=now + timedelta(minutes=5),
    )
    principal = issue_authenticated_principal(principal="agent", authenticated_at=now, mechanism="test-verifier")

    authorize(grant, principal, task="task-1", action="inspect", domains=frozenset({"work"}), collection="notes")


@pytest.mark.parametrize("axis", ["principal", "task", "expired", "action", "domain", "collection"])
def test_authorize_rejects_each_mismatched_axis(axis: str) -> None:
    now = datetime.now(timezone.utc)
    grant = TrustGrant(
        principal="agent" if axis != "principal" else "other",
        task="task-1" if axis != "task" else "other",
        actions=frozenset({"inspect"}) if axis != "action" else frozenset({"write"}),
        domains=frozenset({"work"}) if axis != "domain" else frozenset({"public"}),
        collections=frozenset({"notes"}) if axis != "collection" else frozenset({"other"}),
        expires_at=now + (timedelta(minutes=-1) if axis == "expired" else timedelta(minutes=5)),
    )
    principal = issue_authenticated_principal(principal="agent", authenticated_at=now, mechanism="test-verifier")

    with pytest.raises(AuthorizationError):
        authorize(grant, principal, task="task-1", action="inspect", domains=frozenset({"work"}), collection="notes")
