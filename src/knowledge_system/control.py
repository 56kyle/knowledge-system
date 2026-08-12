"""Read-only inspection and validation of knowledge control authorities."""

from __future__ import annotations

import json
import shutil
import stat
import subprocess
from collections.abc import Hashable
from collections.abc import Sequence
from datetime import datetime
from datetime import timezone
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel
from pydantic import ValidationError

from knowledge_system.codec import load_yaml_mapping
from knowledge_system.codec import plain_mapping
from knowledge_system.digest import digest_named_content
from knowledge_system.domain import CollectionCatalog
from knowledge_system.domain import ControlInspectionReport
from knowledge_system.domain import ControlManifest
from knowledge_system.domain import ControlValidationReport
from knowledge_system.domain import Finding
from knowledge_system.domain import GrantRegistry
from knowledge_system.domain import OwnerGrant
from knowledge_system.domain import ProjectionRecipeRegistry
from knowledge_system.domain import SemanticReleaseRegistry
from knowledge_system.domain import Severity
from knowledge_system.domain import TaskScopedGrant
from knowledge_system.domain import TrustDomainRegistry
from knowledge_system.domain import TrustPolicy
from knowledge_system.exceptions import ConfigurationError
from knowledge_system.profiles import BUILTIN_LOCK_DIGESTS
from knowledge_system.profiles import BUILTIN_PREDICATES
from knowledge_system.schema import rendered_schemas


_ModelT = TypeVar("_ModelT", bound=BaseModel)
_DuplicateT = TypeVar("_DuplicateT", bound=Hashable)
_CONTROL_MANIFEST = "control.yaml"
_SOURCE_REPOSITORY_SEARCH_DEPTH = 4
_CONTROL_ACTIONS = frozenset(
    {
        "administer",
        "read",
        "link",
        "retrieve",
        "synthesize",
        "declassify",
        "update_local_evidence",
        "register",
        "create",
        "set_field",
        "remove_field",
        "replace_subtree",
        "move",
        "reserve_collection",
        "retire_identity",
    }
)


def inspect_control_root(root: Path) -> ControlInspectionReport:
    """Inspect a control repository without modifying it."""
    control_root = _resolve_root(root)
    findings: list[Finding] = []
    input_bytes: dict[str, bytes] = {}
    manifest = _load_control_manifest(control_root, input_bytes, findings)
    catalog: CollectionCatalog | None = None
    domains: TrustDomainRegistry | None = None
    policy: TrustPolicy | None = None
    grants: GrantRegistry | None = None
    releases: SemanticReleaseRegistry | None = None
    recipes: ProjectionRecipeRegistry | None = None
    if manifest is not None:
        catalog = _load_referenced_model(
            control_root, manifest.catalog, CollectionCatalog, "catalog", input_bytes, findings
        )
        domains = _load_referenced_model(
            control_root, manifest.trust_domains, TrustDomainRegistry, "trust-domains", input_bytes, findings
        )
        policy = _load_referenced_model(
            control_root, manifest.trust_policy, TrustPolicy, "trust-policy", input_bytes, findings
        )
        grants = _load_referenced_model(control_root, manifest.grants, GrantRegistry, "grants", input_bytes, findings)
        releases = _load_referenced_model(
            control_root,
            manifest.semantic_releases,
            SemanticReleaseRegistry,
            "semantic-releases",
            input_bytes,
            findings,
        )
        recipes = _load_referenced_model(
            control_root,
            manifest.projection_recipes,
            ProjectionRecipeRegistry,
            "projection-recipes",
            input_bytes,
            findings,
        )
    return ControlInspectionReport(
        control_root=str(control_root),
        manifest=manifest,
        catalog=catalog,
        trust_domains=domains,
        trust_policy=policy,
        grants=grants,
        semantic_releases=releases,
        projection_recipes=recipes,
        bundle_sha256=_bundle_digest(input_bytes) if input_bytes else None,
        knowledge_system_version=_package_version(),
        knowledge_system_revision=_package_revision(),
        exported_schema_sha256=exported_schema_digest(),
        findings=_sorted_findings(findings),
    )


def validate_control_root(root: Path) -> ControlValidationReport:
    """Validate a complete control authority without modifying it."""
    inspection = inspect_control_root(root)
    findings = list(inspection.findings)
    if inspection.trust_domains is not None:
        _validate_domains(inspection.trust_domains, findings)
    if inspection.catalog is not None and inspection.trust_domains is not None:
        _validate_catalog(inspection.catalog, inspection.trust_domains, findings)
    if inspection.trust_policy is not None and inspection.trust_domains is not None:
        _validate_policy(inspection.trust_policy, inspection.trust_domains, findings)
    if inspection.grants is not None and inspection.manifest is not None:
        _validate_grants(
            inspection.grants,
            inspection.manifest,
            inspection.catalog,
            inspection.trust_domains,
            findings,
        )
    if inspection.semantic_releases is not None:
        _validate_semantic_releases(inspection.semantic_releases, findings)
    if inspection.projection_recipes is not None:
        _validate_projection_recipes(
            inspection.projection_recipes,
            inspection.catalog,
            inspection.trust_domains,
            findings,
        )
    return ControlValidationReport(
        control_root=inspection.control_root,
        bundle_sha256=inspection.bundle_sha256,
        knowledge_system_version=inspection.knowledge_system_version,
        knowledge_system_revision=inspection.knowledge_system_revision,
        exported_schema_sha256=inspection.exported_schema_sha256,
        findings=_sorted_findings(findings),
    )


def exported_schema_digest() -> str:
    """Return the deterministic identity of every exported boundary schema."""
    return digest_named_content(rendered_schemas())


def _resolve_root(root: Path) -> Path:
    """Resolve an existing control directory or raise an operational error."""
    try:
        resolved = root.resolve(strict=True)
    except OSError as error:
        raise ConfigurationError(f"control root is unavailable: {root}") from error
    if not resolved.is_dir():
        raise ConfigurationError(f"control root is not a directory: {root}")
    return resolved


def _load_control_manifest(
    root: Path,
    input_bytes: dict[str, bytes],
    findings: list[Finding],
) -> ControlManifest | None:
    """Load the fixed control manifest as invalid content when unavailable."""
    return _load_referenced_model(
        root,
        _CONTROL_MANIFEST,
        ControlManifest,
        "manifest",
        input_bytes,
        findings,
    )


def _load_referenced_model(
    root: Path,
    locator: str,
    model_type: type[_ModelT],
    code: str,
    input_bytes: dict[str, bytes],
    findings: list[Finding],
) -> _ModelT | None:
    """Load one contained manifest reference and retain its raw digest input."""
    relative = Path(locator)
    if relative.is_absolute() or ".." in relative.parts:
        findings.append(_invalid_finding(f"control.{code}-invalid", "path must be contained and relative", locator))
        return None
    try:
        path = (root / relative).resolve(strict=True)
    except (FileNotFoundError, NotADirectoryError) as error:
        findings.append(_invalid_finding(f"control.{code}-invalid", str(error), locator))
        return None
    except OSError as error:
        raise ConfigurationError(f"control path is unavailable: {locator}") from error
    if not path.is_relative_to(root):
        findings.append(
            _invalid_finding(
                f"control.{code}-invalid",
                "path does not resolve to a contained regular file",
                locator,
            )
        )
        return None
    try:
        regular_file = stat.S_ISREG(path.stat().st_mode)
    except (FileNotFoundError, NotADirectoryError) as error:
        findings.append(_invalid_finding(f"control.{code}-invalid", str(error), locator))
        return None
    except OSError as error:
        raise ConfigurationError(f"control path is unavailable: {locator}") from error
    if not regular_file:
        findings.append(
            _invalid_finding(
                f"control.{code}-invalid",
                "path does not resolve to a contained regular file",
                locator,
            )
        )
        return None
    try:
        content = path.read_bytes()
    except OSError as error:
        raise ConfigurationError(f"control file is unreadable: {locator}") from error
    input_bytes[relative.as_posix()] = content
    try:
        return _parse_model(content, path, model_type)
    except (UnicodeDecodeError, ValidationError, ValueError, ConfigurationError) as error:
        findings.append(_invalid_finding(f"control.{code}-invalid", str(error), locator))
        return None


def _parse_model(content: bytes, path: Path, model_type: type[_ModelT]) -> _ModelT:
    """Decode one UTF-8 YAML mapping into a closed boundary model."""
    text = content.decode("utf-8")
    mapping = plain_mapping(load_yaml_mapping(text, source=str(path)))
    return model_type.model_validate(mapping)


def _validate_domains(registry: TrustDomainRegistry, findings: list[Finding]) -> None:
    """Validate unique domains and exact-domain enclave topology."""
    domain_ids = [domain.id for domain in registry.domains]
    _report_duplicates(domain_ids, "trust.domain-duplicate", "trust domain", "trust/domains.yaml", findings)
    known = set(domain_ids)
    enclave_ids = [enclave.id for enclave in registry.enclaves]
    _report_duplicates(enclave_ids, "trust.enclave-duplicate", "trust enclave", "trust/domains.yaml", findings)
    signatures: list[tuple[str, ...]] = []
    for enclave in registry.enclaves:
        unknown = sorted(enclave.domains - known)
        if unknown:
            findings.append(
                _invalid_finding(
                    "trust.enclave-domain-unknown",
                    f"enclave {enclave.id} references unknown domains: {', '.join(unknown)}",
                    "trust/domains.yaml",
                )
            )
        signatures.append(tuple(sorted(enclave.domains)))
    _report_duplicates(
        signatures, "trust.enclave-domain-set-duplicate", "exact enclave domain set", "trust/domains.yaml", findings
    )
    available = set(signatures)
    for domain_id in sorted(known):
        if (domain_id,) not in available:
            findings.append(
                _invalid_finding(
                    "trust.singleton-enclave-missing",
                    f"domain {domain_id} requires a singleton enclave",
                    "trust/domains.yaml",
                )
            )


def _validate_catalog(
    catalog: CollectionCatalog,
    domains: TrustDomainRegistry,
    findings: list[Finding],
) -> None:
    """Validate catalog trust placement against declared singleton domains."""
    known = {domain.id for domain in domains.domains}
    for entry in catalog.collections:
        if len(entry.trust_domains) != 1:
            findings.append(
                _invalid_finding(
                    "catalog.trust-domain-not-singleton",
                    f"collection {entry.collection_id} must declare one trust domain",
                    "catalog/collections.yaml",
                )
            )
        unknown = sorted(entry.trust_domains - known)
        if unknown:
            findings.append(
                _invalid_finding(
                    "catalog.trust-domain-unknown",
                    f"collection {entry.collection_id} references unknown domains: {', '.join(unknown)}",
                    "catalog/collections.yaml",
                )
            )


def _validate_policy(
    policy: TrustPolicy,
    domains: TrustDomainRegistry,
    findings: list[Finding],
) -> None:
    """Validate cross-domain rules without adding implicit permissions."""
    known = {domain.id for domain in domains.domains}
    for index, rule in enumerate(policy.rules):
        unknown = sorted((rule.source_domains | rule.destination_domains) - known)
        if unknown:
            findings.append(
                _invalid_finding(
                    "trust.policy-domain-unknown",
                    f"rule {index} references unknown domains: {', '.join(unknown)}",
                    "trust/policy.yaml",
                )
            )
        invalid = sorted(rule.predicates - BUILTIN_PREDICATES)
        if invalid:
            findings.append(
                _invalid_finding(
                    "trust.policy-predicate-ungoverned",
                    f"rule {index} references ungoverned predicates: {', '.join(invalid)}",
                    "trust/policy.yaml",
                )
            )


def _validate_grants(
    registry: GrantRegistry,
    manifest: ControlManifest,
    catalog: CollectionCatalog | None,
    domains: TrustDomainRegistry | None,
    findings: list[Finding],
) -> None:
    """Validate owner uniqueness and every grant reference."""
    canonical = [
        json.dumps(grant.model_dump(mode="json"), sort_keys=True, separators=(",", ":")) for grant in registry.grants
    ]
    _report_duplicates(canonical, "grant.duplicate", "grant", "trust/grants.yaml", findings)
    owners = [grant for grant in registry.grants if isinstance(grant, OwnerGrant)]
    matching = [grant for grant in owners if grant.principal == manifest.owner]
    if len(owners) != 1 or len(matching) != 1:
        findings.append(
            _invalid_finding(
                "grant.owner-invalid",
                "exactly one permanent owner grant must match the control owner",
                "trust/grants.yaml",
            )
        )
    known_domains: set[str] = {domain.id for domain in domains.domains} if domains is not None else set()
    known_collections: set[str] = (
        {entry.collection_id for entry in catalog.collections} if catalog is not None else set()
    )
    if matching and domains is not None and matching[0].domains != frozenset(known_domains):
        findings.append(
            _invalid_finding(
                "grant.owner-domains-incomplete",
                "owner grant must cover every declared trust domain",
                "trust/grants.yaml",
            )
        )
    if matching and matching[0].actions != _CONTROL_ACTIONS:
        findings.append(
            _invalid_finding(
                "grant.owner-actions-incomplete",
                "owner grant must cover every control action",
                "trust/grants.yaml",
            )
        )
    for grant in registry.grants:
        unknown_domains = sorted(grant.domains - known_domains) if domains is not None else []
        if unknown_domains:
            findings.append(
                _invalid_finding(
                    "grant.domain-unknown",
                    f"grant references unknown domains: {', '.join(unknown_domains)}",
                    "trust/grants.yaml",
                )
            )
        unknown_collections = sorted(grant.collections - known_collections) if catalog is not None else []
        if unknown_collections:
            findings.append(
                _invalid_finding(
                    "grant.collection-unknown",
                    f"grant references unknown collections: {', '.join(unknown_collections)}",
                    "trust/grants.yaml",
                )
            )
        if isinstance(grant, TaskScopedGrant) and not grant.collections:
            findings.append(
                _invalid_finding(
                    "grant.task-collections-required",
                    "task-scoped grants require explicit collections",
                    "trust/grants.yaml",
                )
            )
        if isinstance(grant, TaskScopedGrant) and grant.expires_at <= datetime.now(timezone.utc):
            findings.append(
                _invalid_finding(
                    "grant.expired",
                    "task-scoped grant has expired",
                    "trust/grants.yaml",
                )
            )


def _validate_semantic_releases(registry: SemanticReleaseRegistry, findings: list[Finding]) -> None:
    """Validate semantic ownership and installed built-in digests."""
    entries = (*registry.profiles, *registry.relation_vocabularies)
    keys = [(entry.identifier, entry.version) for entry in entries]
    _report_duplicates(keys, "semantic.release-duplicate", "semantic release", "semantics/releases.yaml", findings)
    profile_keys = {(entry.identifier, entry.version) for entry in registry.profiles}
    vocabulary_keys = {(entry.identifier, entry.version) for entry in registry.relation_vocabularies}
    expected_profiles = {("flap", 1), ("research", 1)}
    expected_vocabularies = {("core@1", 1)}
    for key in sorted(expected_profiles - profile_keys):
        findings.append(
            _invalid_finding(
                "semantic.builtin-missing",
                f"required built-in profile is missing: {key[0]}@{key[1]}",
                "semantics/releases.yaml",
            )
        )
    for key in sorted(expected_vocabularies - vocabulary_keys):
        findings.append(
            _invalid_finding(
                "semantic.builtin-missing",
                f"required built-in relation vocabulary is missing: {key[0]}@{key[1]}",
                "semantics/releases.yaml",
            )
        )
    for key in sorted(profile_keys & expected_vocabularies):
        findings.append(
            _invalid_finding(
                "semantic.builtin-category-invalid",
                f"built-in relation vocabulary is listed as a profile: {key[0]}@{key[1]}",
                "semantics/releases.yaml",
            )
        )
    for key in sorted(vocabulary_keys & expected_profiles):
        findings.append(
            _invalid_finding(
                "semantic.builtin-category-invalid",
                f"built-in profile is listed as a relation vocabulary: {key[0]}@{key[1]}",
                "semantics/releases.yaml",
            )
        )
    for entry in entries:
        expected = BUILTIN_LOCK_DIGESTS.get((entry.identifier, entry.version))
        if expected is not None and entry.sha256 != expected:
            findings.append(
                _invalid_finding(
                    "semantic.builtin-digest-mismatch",
                    f"built-in semantic digest does not match: {entry.identifier}@{entry.version}",
                    "semantics/releases.yaml",
                )
            )


def _validate_projection_recipes(
    registry: ProjectionRecipeRegistry,
    catalog: CollectionCatalog | None,
    domains: TrustDomainRegistry | None,
    findings: list[Finding],
) -> None:
    """Validate recipe identities and owner-authoritative references."""
    _report_duplicates(
        [recipe.id for recipe in registry.recipes],
        "projection.recipe-duplicate",
        "projection recipe",
        "projections/recipes.yaml",
        findings,
    )
    known_collections: set[str] = (
        {entry.collection_id for entry in catalog.collections} if catalog is not None else set()
    )
    known_domains: set[str] = {domain.id for domain in domains.domains} if domains is not None else set()
    for recipe in registry.recipes:
        unknown_collections = sorted(set(recipe.collections) - known_collections)
        unknown_domains = sorted(recipe.trust_domains - known_domains)
        if catalog is not None and unknown_collections:
            findings.append(
                _invalid_finding(
                    "projection.collection-unknown",
                    f"recipe {recipe.id} references unknown collections: {', '.join(unknown_collections)}",
                    "projections/recipes.yaml",
                )
            )
        if domains is not None and unknown_domains:
            findings.append(
                _invalid_finding(
                    "projection.domain-unknown",
                    f"recipe {recipe.id} references unknown domains: {', '.join(unknown_domains)}",
                    "projections/recipes.yaml",
                )
            )


def _report_duplicates(
    values: Sequence[_DuplicateT],
    code: str,
    label: str,
    path: str,
    findings: list[Finding],
) -> None:
    """Report each duplicate registry value once."""
    seen: set[_DuplicateT] = set()
    duplicates: set[_DuplicateT] = set()
    for value in values:
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    for value in sorted(duplicates, key=str):
        findings.append(_invalid_finding(code, f"duplicate {label}: {value}", path))


def _invalid_finding(code: str, message: str, path: str) -> Finding:
    """Create one blocking control-content diagnostic."""
    return Finding(severity=Severity.ERROR, code=code, message=message, path=path)


def _bundle_digest(inputs: dict[str, bytes]) -> str:
    """Digest logical paths and raw bytes without depending on filesystem metadata."""
    return digest_named_content(inputs)


def _package_version() -> str:
    """Report the installed package version, including editable installs."""
    try:
        return version("knowledge-system")
    except PackageNotFoundError:
        return "0+uninstalled"


def _package_revision() -> str:
    """Report a source revision without claiming Git identity when it is unavailable."""
    return _source_revision(Path(__file__).resolve(), _package_version())


def _source_revision(source: Path, distribution_version: str) -> str:
    """Identify a real source tree or return an explicit distribution fallback."""
    repository = next(
        (parent for parent in source.parents[:_SOURCE_REPOSITORY_SEARCH_DEPTH] if (parent / ".git").exists()),
        None,
    )
    git = shutil.which("git")
    if repository is not None and git is not None:
        try:
            head = subprocess.run(  # noqa: S603 -- fixed Git argv; source path is not executed
                [git, "-c", f"safe.directory={repository}", "rev-parse", "HEAD"],
                cwd=repository,
                capture_output=True,
                check=True,
                encoding="utf-8",
                timeout=5,
            ).stdout.strip()
            status = subprocess.run(  # noqa: S603 -- fixed Git argv; source path is not executed
                [git, "-c", f"safe.directory={repository}", "status", "--porcelain"],
                cwd=repository,
                capture_output=True,
                check=True,
                encoding="utf-8",
                timeout=5,
            ).stdout
        except (OSError, subprocess.SubprocessError):
            pass
        else:
            if len(head) == 40 and all(character in "0123456789abcdef" for character in head):
                return f"{head}+dirty" if status else head
    return f"distribution:{distribution_version}"


def _sorted_findings(findings: list[Finding]) -> tuple[Finding, ...]:
    """Return diagnostics in a deterministic public order."""
    return tuple(sorted(findings, key=lambda item: (item.path or "", item.line or 0, item.code, item.message)))
