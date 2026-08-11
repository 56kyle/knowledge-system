"""Knowledge System."""

from pathlib import Path

from knowledge_system.authentication import AuthenticatedPrincipal
from knowledge_system.authentication import LocalFilesystemPrincipal
from knowledge_system.authentication import authenticate_local_filesystem
from knowledge_system.authentication import issue_authenticated_principal
from knowledge_system.collection import inspect_root
from knowledge_system.domain import ApplyContext
from knowledge_system.domain import ApplyResult
from knowledge_system.domain import DomainAnalysis
from knowledge_system.domain import InspectionReport
from knowledge_system.domain import InspectRequest
from knowledge_system.domain import KnowledgeSnapshot
from knowledge_system.domain import MutationPlan
from knowledge_system.domain import MutationRequest
from knowledge_system.domain import RegisterMutationPayload
from knowledge_system.domain import RegistrationRequest
from knowledge_system.domain import ResolutionContext
from knowledge_system.domain import ResolutionResult
from knowledge_system.domain import RetirementPayload
from knowledge_system.domain import ReviewBasis
from knowledge_system.domain import ValidateRequest
from knowledge_system.domain import ValidationReport
from knowledge_system.mutation import apply_mutation
from knowledge_system.mutation import plan_mutation
from knowledge_system.mutation import plan_registration
from knowledge_system.resolution import parse_reference
from knowledge_system.resolution import resolve_reference
from knowledge_system.review import compute_review_basis
from knowledge_system.trust import compute_effective_domains
from knowledge_system.validation import validate_external_context
from knowledge_system.validation import validate_root


__all__ = [
    "ApplyContext",
    "ApplyResult",
    "AuthenticatedPrincipal",
    "DomainAnalysis",
    "InspectRequest",
    "InspectionReport",
    "KnowledgeSnapshot",
    "LocalFilesystemPrincipal",
    "MutationPlan",
    "MutationRequest",
    "RegisterMutationPayload",
    "RegistrationRequest",
    "ResolutionContext",
    "ResolutionResult",
    "RetirementPayload",
    "ReviewBasis",
    "ValidateRequest",
    "ValidationReport",
    "apply_mutation",
    "authenticate_local_filesystem",
    "compute_effective_domains",
    "compute_review_basis",
    "inspect_collection",
    "issue_authenticated_principal",
    "parse_reference",
    "plan_mutation",
    "plan_registration",
    "resolve_reference",
    "validate_collection",
]


def inspect_collection(request: InspectRequest) -> InspectionReport:
    """Inspect a collection through the stable public request boundary."""
    manifest = Path(request.manifest) if request.manifest else None
    return inspect_root(Path(request.collection), manifest_path=manifest)


def validate_collection(request: ValidateRequest) -> ValidationReport:
    """Validate a collection through the stable public request boundary."""
    manifest = Path(request.manifest) if request.manifest else None
    report = validate_root(Path(request.collection), manifest_path=manifest)
    return validate_external_context(request, report)
