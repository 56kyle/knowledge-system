"""Authentication boundary values for the knowledge_system package."""

from __future__ import annotations

import getpass
import os
from dataclasses import dataclass
from datetime import datetime
from datetime import timezone

from knowledge_system.exceptions import AuthorizationError


_AUTHENTICATOR_SEAL = object()


@dataclass(frozen=True, slots=True, init=False)
class AuthenticatedPrincipal:
    """Identity evidence that can only be issued through an authenticator."""

    principal: str
    authenticated_at: datetime
    mechanism: str

    def __init__(
        self,
        principal: str,
        authenticated_at: datetime,
        mechanism: str,
        *,
        _seal: object,
    ) -> None:
        """Build sealed identity evidence for an authenticator."""
        if _seal is not _AUTHENTICATOR_SEAL:
            raise AuthorizationError("principal was not produced by an authenticator")
        if authenticated_at.tzinfo is None or authenticated_at.utcoffset() is None:
            raise AuthorizationError("authentication time must be timezone-aware")
        object.__setattr__(self, "principal", principal)
        object.__setattr__(self, "authenticated_at", authenticated_at.astimezone(timezone.utc))
        object.__setattr__(self, "mechanism", mechanism)


@dataclass(frozen=True, slots=True, init=False)
class LocalFilesystemPrincipal(AuthenticatedPrincipal):
    """OS identity used by the local CLI filesystem security boundary."""


def authenticate_local_filesystem() -> LocalFilesystemPrincipal:
    """Issue a principal from the current operating-system account."""
    account = getpass.getuser()
    domain = os.environ.get("USERDOMAIN")
    identity = f"{domain}\\{account}" if domain else account
    return LocalFilesystemPrincipal(
        identity,
        datetime.now(timezone.utc),
        "local-filesystem-os-account",
        _seal=_AUTHENTICATOR_SEAL,
    )


def issue_authenticated_principal(
    *,
    principal: str,
    authenticated_at: datetime,
    mechanism: str,
) -> AuthenticatedPrincipal:
    """Issue a principal after an integration authenticator verifies evidence."""
    if not mechanism or mechanism == "asserted":
        raise AuthorizationError("an authenticated mechanism is required")
    return AuthenticatedPrincipal(
        principal,
        authenticated_at,
        mechanism,
        _seal=_AUTHENTICATOR_SEAL,
    )
