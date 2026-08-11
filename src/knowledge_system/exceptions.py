"""Explicit failure contracts for the knowledge_system package."""


class KnowledgeSystemError(Exception):
    """Base class for operational knowledge-system failures."""


class ConfigurationError(KnowledgeSystemError):
    """Raised when collection configuration cannot be loaded."""


class ReferenceSyntaxError(KnowledgeSystemError, ValueError):
    """Raised when a canonical reference has invalid syntax."""


class ReferenceResolutionError(KnowledgeSystemError):
    """Raised when an authorized canonical reference cannot be resolved."""


class AuthorizationError(KnowledgeSystemError):
    """Raised when the principal may not perform the requested operation."""


class MutationPlanningError(KnowledgeSystemError):
    """Raised when a safe mutation plan cannot be produced."""


class MutationConflictError(KnowledgeSystemError):
    """Raised before writes when mutation preconditions are stale."""


class ApplyIndeterminateError(KnowledgeSystemError):
    """Raised when a multi-file apply cannot prove rollback succeeded."""
