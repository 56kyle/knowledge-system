"""Command-line interface for knowledge_system."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping
from datetime import date
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import cast

import typer
from pydantic import BaseModel
from pydantic import ValidationError
from typing_extensions import Annotated

from knowledge_system import inspect_collection
from knowledge_system import inspect_control
from knowledge_system import validate_collection
from knowledge_system import validate_control
from knowledge_system.authentication import authenticate_local_filesystem
from knowledge_system.domain import ApplyContext
from knowledge_system.domain import ControlInspectionReport
from knowledge_system.domain import ControlInspectRequest
from knowledge_system.domain import ControlValidateRequest
from knowledge_system.domain import ControlValidationReport
from knowledge_system.domain import InspectionReport
from knowledge_system.domain import InspectRequest
from knowledge_system.domain import MutationPlan
from knowledge_system.domain import MutationRequest
from knowledge_system.domain import Origin
from knowledge_system.domain import RegistrationRequest
from knowledge_system.domain import Severity
from knowledge_system.domain import ValidateRequest
from knowledge_system.domain import ValidationReport
from knowledge_system.exceptions import ApplyIndeterminateError
from knowledge_system.exceptions import ConfigurationError
from knowledge_system.exceptions import KnowledgeSystemError
from knowledge_system.exceptions import MutationConflictError
from knowledge_system.mutation import apply_mutation
from knowledge_system.mutation import approve_mutation
from knowledge_system.mutation import plan_mutation
from knowledge_system.mutation import plan_registration
from knowledge_system.review import compute_review_basis
from knowledge_system.schema import export_schemas
from knowledge_system.validation import reverse_impact


EXIT_VALIDATION = 1
EXIT_OPERATIONAL = 2
EXIT_CONFLICT = 3
EXIT_INDETERMINATE = 4
_CURRENT_DIRECTORY = Path()
_SCHEMA_DIRECTORY = Path("schemas")


class OutputFormat(str, Enum):
    """Supported deterministic output formats."""

    TEXT = "text"
    JSON = "json"


app = typer.Typer(
    help="Inspect, validate, and safely mutate canonical Markdown knowledge collections.",
    invoke_without_command=True,
)
mutation_app = typer.Typer(help="Plan or apply typed collection mutations.")
review_app = typer.Typer(help="Compute revision-scoped review values.")
schema_app = typer.Typer(help="Export versioned JSON Schema contracts.")
control_app = typer.Typer(help="Inspect and validate a human-owned control authority.")
app.add_typer(mutation_app, name="mutation")
app.add_typer(review_app, name="review")
app.add_typer(schema_app, name="schema")
app.add_typer(control_app, name="control")


@app.callback()
def root_command(context: typer.Context) -> None:
    """Show command help when no operation was selected."""
    if context.invoked_subcommand is None:
        _echo(context.get_help())


def _repo_roots(values: list[str]) -> dict[str, str]:
    """Parse repeated NAME=PATH deployment locators."""
    roots: dict[str, str] = {}
    for value in values:
        name, separator, path = value.partition("=")
        if not name or separator != "=" or not path or name in roots:
            raise typer.BadParameter(f"invalid or duplicate repo root: {value}")
        roots[name] = str(Path(path).resolve())
    return roots


def _echo(value: str, *, error: bool = False) -> None:
    """Render arbitrary Unicode safely on legacy Windows consoles."""
    encoding = (sys.stderr.encoding if error else sys.stdout.encoding) or "utf-8"
    safe = value.encode(encoding, errors="backslashreplace").decode(encoding)
    typer.echo(safe, err=error)


def _emit_model(
    model: InspectionReport | ValidationReport,
    output_format: OutputFormat,
) -> None:
    """Render a Pydantic result as stable JSON or concise text."""
    if output_format is OutputFormat.JSON:
        _echo(
            json.dumps(
                model.model_dump(mode="json"),
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
            )
        )
        return
    _echo(f"collection: {model.collection_root}")
    if isinstance(model, InspectionReport):
        _echo(f"notes: {len(model.notes)}")
    for finding in model.findings:
        location = finding.path or "collection"
        if finding.line:
            location = f"{location}:{finding.line}"
        _echo(f"{finding.severity.value}: {finding.code}: {location}: {finding.message}")
    if not model.findings:
        _echo("findings: none")


def _emit_control_model(
    model: ControlInspectionReport | ControlValidationReport,
    output_format: OutputFormat,
) -> None:
    """Render a control result as stable JSON or concise text."""
    if output_format is OutputFormat.JSON:
        _echo(json.dumps(_canonical_json_value(model), ensure_ascii=True, indent=2, sort_keys=True))
        return
    _echo(f"control: {model.control_root}")
    _echo(f"bundle_sha256: {model.bundle_sha256 or 'unavailable'}")
    _echo(f"knowledge_system_version: {model.knowledge_system_version}")
    _echo(f"knowledge_system_revision: {model.knowledge_system_revision}")
    _echo(f"exported_schema_sha256: {model.exported_schema_sha256}")
    for finding in model.findings:
        _echo(f"{finding.severity.value}: {finding.code}: {finding.path or 'control'}: {finding.message}")
    if not model.findings:
        _echo("findings: none")


def _canonical_json_value(value: object) -> object:
    """Convert a model value to JSON primitives with stable unordered collections."""
    if isinstance(value, BaseModel):
        dumped = cast("object", value.model_dump(mode="python"))
        return _canonical_json_value(dumped)
    if isinstance(value, Mapping):
        mapping = cast("Mapping[object, object]", value)
        ordered = sorted(mapping.items(), key=lambda pair: str(pair[0]))
        return {str(key): _canonical_json_value(item) for key, item in ordered}
    if isinstance(value, (set, frozenset)):
        values = cast("set[object] | frozenset[object]", value)
        normalized = [_canonical_json_value(item) for item in values]
        return sorted(normalized, key=lambda item: json.dumps(item, sort_keys=True))
    if isinstance(value, (tuple, list)):
        values = cast("tuple[object, ...] | list[object]", value)
        return [_canonical_json_value(item) for item in values]
    if isinstance(value, Enum):
        return _canonical_json_value(cast("object", value.value))
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"unsupported JSON boundary value: {type(value).__name__}")


@control_app.command("inspect")
def control_inspect_command(
    root: Annotated[Path, typer.Argument(exists=True, file_okay=False)] = _CURRENT_DIRECTORY,
    output_format: Annotated[OutputFormat, typer.Option("--format")] = OutputFormat.TEXT,
) -> None:
    """Inspect a control authority without changing it."""
    try:
        report = inspect_control(ControlInspectRequest(root=str(root)))
        _emit_control_model(report, output_format)
        if any(finding.severity in {Severity.ERROR, Severity.CRITICAL} for finding in report.findings):
            raise typer.Exit(EXIT_VALIDATION)
    except (KnowledgeSystemError, OSError, ValidationError) as error:
        _handle_error(error)


@control_app.command("validate")
def control_validate_command(
    root: Annotated[Path, typer.Argument(exists=True, file_okay=False)] = _CURRENT_DIRECTORY,
    output_format: Annotated[OutputFormat, typer.Option("--format")] = OutputFormat.TEXT,
) -> None:
    """Validate a complete control authority without changing it."""
    try:
        report = validate_control(ControlValidateRequest(root=str(root)))
        _emit_control_model(report, output_format)
        if report.has_blocking_findings:
            raise typer.Exit(EXIT_VALIDATION)
    except (KnowledgeSystemError, OSError, ValidationError) as error:
        _handle_error(error)


def _handle_error(error: Exception) -> None:
    """Map explicit application errors to the public CLI exit contract."""
    _echo(f"error: {error}", error=True)
    if isinstance(error, MutationConflictError):
        raise typer.Exit(EXIT_CONFLICT) from error
    if isinstance(error, ApplyIndeterminateError):
        raise typer.Exit(EXIT_INDETERMINATE) from error
    raise typer.Exit(EXIT_OPERATIONAL) from error


@app.command("inspect")
def inspect_command(
    collection: Annotated[Path, typer.Argument(exists=True, file_okay=False)] = _CURRENT_DIRECTORY,
    catalog: Annotated[Path | None, typer.Option(exists=True, dir_okay=False)] = None,
    repo_root: Annotated[list[str] | None, typer.Option("--repo-root")] = None,
    output_format: Annotated[OutputFormat, typer.Option("--format")] = OutputFormat.TEXT,
) -> None:
    """Inspect a collection without changing it."""
    try:
        report = inspect_collection(
            InspectRequest(
                collection=str(collection),
                catalog=str(catalog) if catalog else None,
                repo_roots=_repo_roots(repo_root or []),
            )
        )
        _emit_model(report, output_format)
        if any(finding.severity.value in {"error", "critical"} for finding in report.findings):
            raise typer.Exit(EXIT_VALIDATION)
    except (KnowledgeSystemError, OSError, ValidationError) as error:
        _handle_error(error)


@app.command("validate")
def validate_command(
    collection: Annotated[Path, typer.Argument(exists=True, file_okay=False)] = _CURRENT_DIRECTORY,
    catalog: Annotated[Path | None, typer.Option(exists=True, dir_okay=False)] = None,
    repo_root: Annotated[list[str] | None, typer.Option("--repo-root")] = None,
    output_format: Annotated[OutputFormat, typer.Option("--format")] = OutputFormat.TEXT,
) -> None:
    """Validate canonical collection contracts without changing files."""
    try:
        report = validate_collection(
            ValidateRequest(
                collection=str(collection),
                catalog=str(catalog) if catalog else None,
                repo_roots=_repo_roots(repo_root or []),
            )
        )
        _emit_model(report, output_format)
        if report.has_blocking_findings:
            raise typer.Exit(EXIT_VALIDATION)
    except (KnowledgeSystemError, OSError, ValidationError) as error:
        _handle_error(error)


@app.command("register")
def register_command(
    note: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    collection: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    actor: Annotated[str, typer.Option()],
    task: Annotated[str, typer.Option()],
    plan_out: Annotated[Path | None, typer.Option(dir_okay=False)] = None,
    requested_id: Annotated[str | None, typer.Option("--id")] = None,
    profile: Annotated[list[str] | None, typer.Option("--profile")] = None,
    origin: Annotated[Origin, typer.Option("--origin")] = Origin.AGENT,
    apply: Annotated[bool, typer.Option("--apply")] = False,
    stdout: Annotated[bool, typer.Option("--stdout")] = False,
) -> None:
    """Plan registration and apply it only when explicitly requested."""
    try:
        if stdout and apply:
            raise ConfigurationError("--stdout and --apply are mutually exclusive")
        if (plan_out is None) == (not stdout):
            raise ConfigurationError("choose exactly one of --plan-out or --stdout")
        root = collection.resolve(strict=True)
        resolved_note = note.resolve(strict=True)
        relative_note = resolved_note.relative_to(root).as_posix()
        plan = plan_registration(
            RegistrationRequest(
                note=relative_note,
                collection=str(root),
                actor=actor,
                task=task,
                origin=origin,
                requested_id=requested_id,
                profiles=tuple(profile or []),
            )
        )
        if stdout:
            _echo(plan.model_dump_json(indent=2))
        else:
            if plan_out is None:
                raise ConfigurationError("--plan-out is required without --stdout")
            _write_plan_exclusive(plan_out, plan)
            _echo(f"plan: {plan_out}")
        diff = "".join(file.diff for file in plan.files)
        if diff:
            _echo(diff, error=stdout)
        if apply:
            result = apply_mutation(plan, _apply_context(plan))
            _echo(f"applied: {len(result.written_paths)} file(s)")
    except (KnowledgeSystemError, OSError, ValidationError, ValueError) as error:
        _handle_error(error)


@mutation_app.command("plan")
def mutation_plan_command(
    request: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    out: Annotated[Path | None, typer.Option(dir_okay=False)] = None,
    stdout: Annotated[bool, typer.Option("--stdout")] = False,
) -> None:
    """Plan one typed mutation request from JSON."""
    try:
        if (out is None) == (not stdout):
            raise ConfigurationError("choose exactly one of --out or --stdout")
        model = MutationRequest.model_validate_json(request.read_text(encoding="utf-8"))
        plan = plan_mutation(model)
        if stdout:
            _echo(plan.model_dump_json(indent=2))
        else:
            if out is None:
                raise ConfigurationError("--out is required without --stdout")
            _write_plan_exclusive(out, plan)
            _echo(f"plan: {out}")
    except (KnowledgeSystemError, OSError, ValidationError) as error:
        _handle_error(error)


@mutation_app.command("apply")
def mutation_apply_command(
    plan_path: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    approve: Annotated[bool, typer.Option("--approve")] = False,
    recover_lock: Annotated[bool, typer.Option("--recover-lock")] = False,
) -> None:
    """Apply a previously reviewed mutation plan."""
    try:
        plan = MutationPlan.model_validate_json(plan_path.read_text(encoding="utf-8"))
        result = apply_mutation(plan, _apply_context(plan, approve=approve, recover_lock=recover_lock))
        _echo(result.model_dump_json(indent=2))
    except (KnowledgeSystemError, OSError, ValidationError) as error:
        _handle_error(error)


def _apply_context(
    plan: MutationPlan,
    *,
    approve: bool = False,
    recover_lock: bool = False,
) -> ApplyContext:
    """Create the CLI's OS-authenticated local filesystem context."""
    principal = authenticate_local_filesystem()
    return ApplyContext(
        principal=principal,
        expected_operation_id=plan.operation_id,
        approval=approve_mutation(plan, principal) if approve else None,
        recover_lock=recover_lock,
    )


def _write_plan_exclusive(path: Path, plan: MutationPlan) -> None:
    """Create one regular plan file exclusively and durably."""
    parent = path.parent.resolve(strict=True)
    candidate = parent / path.name
    if candidate.exists() or candidate.is_symlink():
        raise OSError(f"plan output already exists: {candidate}")
    collection_root = Path(plan.collection).resolve(strict=True)
    planned_targets = {(collection_root / item.path).resolve(strict=False) for item in plan.files}
    if candidate.resolve(strict=False) in planned_targets:
        raise OSError("plan output collides with a planned mutation target")
    descriptor = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            _ = stream.write(plan.model_dump_json(indent=2) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        candidate.unlink(missing_ok=True)
        raise


@review_app.command("basis")
def review_basis_command(
    note: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
) -> None:
    """Compute the review basis for one Markdown note."""
    try:
        _echo(compute_review_basis(note.read_bytes()).reference)
    except (KnowledgeSystemError, OSError, ValidationError) as error:
        _handle_error(error)


@app.command("impact")
def impact_command(
    reference: str,
    collection: Annotated[Path, typer.Option(exists=True, file_okay=False)],
) -> None:
    """List registered notes transitively affected by a reference."""
    try:
        for affected in reverse_impact(reference, collection):
            _echo(affected)
    except (KnowledgeSystemError, OSError, ValidationError) as error:
        _handle_error(error)


@schema_app.command("export")
def schema_export_command(
    destination: Annotated[Path, typer.Option("--destination")] = _SCHEMA_DIRECTORY,
    check: Annotated[bool, typer.Option("--check")] = False,
) -> None:
    """Export deterministic schemas or fail when committed schemas drift."""
    drifted = export_schemas(destination, check=check)
    if check and drifted:
        _echo("schema drift: " + ", ".join(drifted), error=True)
        raise typer.Exit(EXIT_VALIDATION)
    _echo(f"schemas: {len(drifted)} {'updated' if not check else 'checked'}")


if __name__ == "__main__":
    app()  # pragma: no cover
