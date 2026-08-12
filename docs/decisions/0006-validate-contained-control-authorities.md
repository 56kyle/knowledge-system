# 0006 - Validate contained control authority bundles

## Status

Accepted

## Context and problem statement

`knowledge-system` validates individual collection catalogs, trust policies, grants, semantic locks, and projection recipes. The knowledge network also needs one validation boundary for the human-owned repository that composes these contracts.

## Decision drivers

- One stable Python and CLI boundary
- Read-only inspection and validation
- Closed and immutable boundary models
- Deterministic bundle and schema identities
- Duplicate detection in owner-maintained registries
- Path containment without rejecting safe contained symlinks
- Clear separation between invalid content and operational failure

## Considered options

### Validate each file independently in `knowledge-control`

- Good: no core package changes.
- Bad: composition rules and security boundaries would live outside `knowledge-system`.

### Add executable policy behavior to `knowledge-control`

- Good: direct repository-local customization.
- Bad: creates a second implementation authority and permits policy code beside policy data.

### Add a bounded control bundle to `knowledge-system`

- Good: keeps semantics and validation in one package.
- Good: lets `knowledge-control` remain declarative.
- Bad: expands the public model and schema surface.

## Decision outcome

Add frozen control manifest, trust-domain registry, enclave, owner grant, task-scoped grant, grant registry, semantic release registry, projection recipe registry, request, and report models. Keep owner and task-scoped grants untagged in YAML. Validate their distinct field contracts through the union: owners use task `*` without expiry; task-scoped grants use a bounded task, explicit collections, and an aware expiry.

Use lowercase `snake_case` literals for all control action identifiers. Preserve the existing `TrustGrant` contract for collection mutation authorization.

Expose `inspect_control` and `validate_control`, plus `kn control inspect` and `kn control validate`. Invalid repository content returns blocking findings and CLI exit code `1`. An unavailable root or another operational failure returns exit code `2`.

Resolve `control.yaml` and every manifest reference through the same strict boundary. Reject absolute paths and `..` components. Require each resolved target to be a regular file inside the resolved control root. Accept a symlink only when its final target remains inside that root. Report missing, nonregular, and escaping paths as invalid content. Treat permission and transient filesystem failures as operational errors.

Compute bundle and exported-schema identities from canonical sorted records that contain each logical path and the SHA-256 digest of its bytes. This framing prevents ambiguity between adjacent path and content values. Include the installed package version, exported-schema digest, and explicit package revision in each report. A local Git source reports its 40-character commit with an optional `+dirty` marker. A source without usable Git metadata reports `distribution:<package-version>` and does not claim a commit identity.

Bound Git discovery to the source package's repository layout. Invoke Git with a command-local safe-directory value for that discovered repository. This permits read-only revision inspection when a sandbox process has a different operating-system identity, without changing global Git configuration.

## Consequences

- Control consumers can bind to stable Pydantic and JSON Schema contracts.
- Sequence registries preserve duplicate IDs for deterministic findings.
- Inspection can return partial parsed state with findings.
- A missing cross-domain rule does not create permission.
- Package or schema drift is visible in local validation output.

## Confirmation

- Export schemas twice and compare all bytes.
- Validate real temporary control repositories without mocks.
- Verify CLI exit codes `0`, `1`, and `2`.
- Compare source bytes and modification times before and after read-only operations.

## References

- `src/knowledge_system/control.py`
- `src/knowledge_system/domain.py`
- ADR 0004 for authorization and opaque denial
