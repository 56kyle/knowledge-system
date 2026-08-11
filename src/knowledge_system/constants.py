"""Constants for the knowledge_system package."""

from pydantic import ConfigDict


SCHEMA_VERSION = 1
DEFAULT_PYDANTIC_CONFIG: ConfigDict = ConfigDict(
    extra="forbid",
    frozen=True,
    validate_default=True,
)
