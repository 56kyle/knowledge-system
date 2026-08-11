# 0001 - Make frozen Pydantic models the schema authority

## Status

Accepted

## Context and problem statement

The local core needs one precise contract for Python callers, CLI JSON, YAML validation, mutation plans, and generated JSON Schema. Separate handwritten representations can drift and admit states that another subsystem rejects. Public values must also stay immutable after validation, including nested collections.

## Decision drivers

- One versioned authority for validation, serialization, and schema generation
- Closed boundaries that reject unknown keys and unsupported versions
- Deeply immutable public values
- Deterministic JSON Schema for downstream implementations
- Python 3.10 through 3.14 support

## Considered options

### Frozen Pydantic models

- Good: combines runtime validation, typed access, serialization, and schema output.
- Good: supports explicit cross-field invariants and frozen top-level values.
- Bad: adds a runtime dependency and requires explicit handling for nested mutability.

### Dataclasses with separate validators and schemas

- Good: uses the standard library for domain values.
- Bad: duplicates field definitions and makes drift likely.
- Bad: requires a separate validation and schema-generation system.

### TypedDict with procedural validation

- Good: closely resembles wire mappings.
- Bad: provides no runtime invariant or immutability guarantee.
- Bad: makes failure contracts depend on scattered procedural code.

## Decision outcome

Use Pydantic 2 frozen models with `extra="forbid"` and validated defaults. Models are authoritative. Nested sequences become tuples or frozen sets, nested mappings are exposed through immutable mapping values, and behavior-bearing nested records use typed frozen models. Files under `schemas/` are reproducible projections, not a second authority. Custom profiles cannot own base, built-in, or reserved fields and must declare their own prefix.

## Consequences

- Boundary failures are typed and occur before unvalidated data enters core logic.
- Schema changes require an explicit version decision and regenerated schemas.
- Pydantic is a required runtime dependency.
- Code must avoid public `dict`, `list`, or unvalidated object-shaped state where a typed contract exists.

## Confirmation

- `kn schema export --check` detects schema drift.
- basedpyright reports zero errors and warnings for production source.
- Contract tests attempt nested mutation and unknown-key input.
- Profile tests reject reserved ownership and every unsupported invariant form.

## References

- Pydantic frozen models and JSON Schema documentation
- `src/knowledge_system/domain.py`
- `src/knowledge_system/immutable.py`
