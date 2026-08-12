"""Trust authorization and monotonic domain propagation."""

from __future__ import annotations

from datetime import datetime
from datetime import timezone
from typing import TYPE_CHECKING

from knowledge_system.domain import DomainAnalysis
from knowledge_system.domain import KnowledgeSnapshot
from knowledge_system.domain import TrustGrant
from knowledge_system.domain import TrustPolicy
from knowledge_system.exceptions import AuthorizationError


if TYPE_CHECKING:
    from knowledge_system.authentication import AuthenticatedPrincipal


def authorize(
    grant: TrustGrant,
    principal: AuthenticatedPrincipal,
    *,
    task: str,
    action: str,
    domains: frozenset[str],
    collection: str | None = None,
) -> None:
    """Authorize one operation or raise AuthorizationError without target disclosure."""
    now = datetime.now(timezone.utc)
    expiry = grant.expires_at.astimezone(timezone.utc)
    if grant.principal != principal.principal or grant.task != task:
        raise AuthorizationError("principal context does not match the grant")
    if expiry <= now:
        raise AuthorizationError("authorization grant has expired")
    if action not in grant.actions or not domains.issubset(grant.domains):
        raise AuthorizationError("operation is not authorized")
    if collection is not None and collection not in grant.collections:
        raise AuthorizationError("operation is not authorized")


def relation_is_allowed(
    policy: TrustPolicy,
    *,
    source_domains: frozenset[str],
    destination_domains: frozenset[str],
    predicate: str,
) -> bool:
    """Return whether a same- or cross-domain relation is explicitly allowed."""
    if source_domains == destination_domains:
        return True
    return any(
        source_domains == rule.source_domains
        and destination_domains == rule.destination_domains
        and predicate in rule.predicates
        for rule in policy.rules
    )


def compute_effective_domains(snapshot: KnowledgeSnapshot) -> DomainAnalysis:
    """Propagate referenced target domains to sources until a fixed point."""
    effective = {node: set(domains) for node, domains in snapshot.node_domains.items()}
    changed = True
    while changed:
        changed = False
        for edge in snapshot.edges:
            source = effective.setdefault(edge.source, set())
            target = effective.setdefault(edge.target, set())
            previous = len(source)
            source.update(target)
            changed = changed or len(source) != previous
    return DomainAnalysis(effective_domains={node: frozenset(domains) for node, domains in sorted(effective.items())})


def select_exact_domain_enclave(
    analysis: DomainAnalysis,
    domains: frozenset[str],
) -> tuple[str, ...]:
    """Select only nodes whose effective domain set exactly matches the enclave."""
    return tuple(node for node, effective in sorted(analysis.effective_domains.items()) if effective == domains)
