# pyright: reportUnusedCallResult=false

import json
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from hashlib import sha256
from pathlib import Path

import pytest

from knowledge_system.authentication import AuthenticatedPrincipal
from knowledge_system.authentication import authenticate_local_filesystem
from knowledge_system.authentication import issue_authenticated_principal
from knowledge_system.domain import ApplyContext
from knowledge_system.domain import MutationRequest
from knowledge_system.domain import TrustGrant
from knowledge_system.domain import TrustPolicy
from knowledge_system.exceptions import AuthorizationError
from knowledge_system.exceptions import MutationPlanningError
from knowledge_system.mutation import apply_mutation
from knowledge_system.mutation import approve_mutation
from knowledge_system.mutation import plan_mutation
from tests.helpers import write_manifest


def _policy_digest(policy: TrustPolicy) -> str:
    payload = json.dumps(policy.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(payload.encode()).hexdigest()


def _principal(name: str = "verified-agent") -> AuthenticatedPrincipal:
    return issue_authenticated_principal(
        principal=name,
        authenticated_at=datetime.now(timezone.utc),
        mechanism="integration-authenticator",
    )


def _grant(*, action: str = "create", expired: bool = False) -> TrustGrant:
    return TrustGrant(
        principal="verified-agent",
        task="task-1",
        actions=frozenset({action}),
        domains=frozenset({"work"}),
        collections=frozenset({"local-notes"}),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=-1 if expired else 5),
    )


def _set_tier(root: Path, tier: str) -> None:
    manifest = root / "collection.yaml"
    manifest.write_text(
        manifest.read_text(encoding="utf-8")
        + (
            "agents:\n"
            f"  direct: [{'' if tier != 'direct' else 'create'}]\n"
            f"  review_required: [{'' if tier != 'review_required' else 'create'}]\n"
            f"  explicit_authorization: [{'' if tier != 'explicit_authorization' else 'create'}]\n"
        ),
        encoding="utf-8",
    )


def _create_request(root: Path, **values: object) -> MutationRequest:
    return MutationRequest.model_validate(
        {
            "intent": "create",
            "collection": str(root),
            "actor": "note-author",
            "task": "task-1",
            "path": "new.md",
            "value": "# New\n",
            **values,
        }
    )


def test_direct_tier_needs_no_approval_for_local_principal(tmp_path: Path) -> None:
    write_manifest(tmp_path)
    _set_tier(tmp_path, "direct")
    plan = plan_mutation(_create_request(tmp_path))
    context = ApplyContext(principal=authenticate_local_filesystem(), expected_operation_id=plan.operation_id)
    apply_mutation(plan, context)
    assert (tmp_path / "new.md").exists()


def test_review_required_tier_requires_matching_owner_approval(tmp_path: Path) -> None:
    write_manifest(tmp_path)
    _set_tier(tmp_path, "review_required")
    plan = plan_mutation(_create_request(tmp_path))
    principal = authenticate_local_filesystem()
    without = ApplyContext(principal=principal, expected_operation_id=plan.operation_id)
    with pytest.raises(AuthorizationError):
        apply_mutation(plan, without)
    approved = ApplyContext(
        principal=principal,
        expected_operation_id=plan.operation_id,
        approval=approve_mutation(plan, principal),
    )
    apply_mutation(plan, approved)
    assert (tmp_path / "new.md").exists()


def test_explicit_tier_requires_approval_and_external_grant(tmp_path: Path) -> None:
    write_manifest(tmp_path, trust_policy="trust-policy.yaml", trust_policy_id="local-trust")
    _set_tier(tmp_path, "explicit_authorization")
    (tmp_path / "trust-policy.yaml").write_text("version: 1\nid: local-trust\nrules: []\n", encoding="utf-8")
    grant = _grant()
    plan = plan_mutation(_create_request(tmp_path, trust_grant=grant))
    principal = _principal()
    approved = approve_mutation(plan, principal)
    missing_grant = ApplyContext(
        principal=principal,
        expected_operation_id=plan.operation_id,
        approval=approved,
    )
    with pytest.raises(AuthorizationError):
        apply_mutation(plan, missing_grant)
    context = ApplyContext(
        principal=principal,
        expected_operation_id=plan.operation_id,
        trust_grant=grant,
        approval=approved,
    )
    apply_mutation(plan, context)
    assert (tmp_path / "new.md").exists()


@pytest.mark.parametrize("grant", [_grant(action="move"), _grant(expired=True)])
def test_explicit_tier_rejects_invalid_grant(tmp_path: Path, grant: TrustGrant) -> None:
    write_manifest(tmp_path, trust_policy="trust-policy.yaml", trust_policy_id="local-trust")
    _set_tier(tmp_path, "explicit_authorization")
    (tmp_path / "trust-policy.yaml").write_text("version: 1\nid: local-trust\nrules: []\n", encoding="utf-8")
    plan = plan_mutation(_create_request(tmp_path, trust_grant=grant))
    principal = _principal()
    context = ApplyContext(
        principal=principal,
        expected_operation_id=plan.operation_id,
        trust_grant=grant,
        approval=approve_mutation(plan, principal),
    )
    with pytest.raises(AuthorizationError):
        apply_mutation(plan, context)


def test_contained_policy_path_cannot_escape_collection(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-policy.yaml"
    outside.write_text("version: 1\nid: policy\nrules: []\n", encoding="utf-8")
    write_manifest(tmp_path, trust_policy="../" + outside.name, trust_policy_id="policy")
    with pytest.raises(MutationPlanningError):
        plan_mutation(_create_request(tmp_path))


def test_contained_policy_identity_must_match_manifest(tmp_path: Path) -> None:
    write_manifest(tmp_path, trust_policy="trust-policy.yaml", trust_policy_id="expected")
    (tmp_path / "trust-policy.yaml").write_text("version: 1\nid: actual\nrules: []\n", encoding="utf-8")
    with pytest.raises(MutationPlanningError):
        plan_mutation(_create_request(tmp_path))


def test_external_policy_requires_explicit_identity_and_digest_expectation(tmp_path: Path) -> None:
    write_manifest(tmp_path)
    policy = TrustPolicy(id="external")
    with pytest.raises(MutationPlanningError):
        plan_mutation(_create_request(tmp_path, trust_policy=policy))

    plan = plan_mutation(
        _create_request(
            tmp_path,
            trust_policy=policy,
            expected_policy_id=policy.id,
            expected_policy_sha256=_policy_digest(policy),
        )
    )
    context = ApplyContext(
        principal=authenticate_local_filesystem(),
        expected_operation_id=plan.operation_id,
        trust_policy=policy,
    )
    apply_mutation(plan, context)
    assert (tmp_path / "new.md").exists()
