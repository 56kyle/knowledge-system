# 0004 - Authorize before resolving protected references

## Status

Accepted

## Context and problem statement

Catalog and filesystem lookup can disclose that an excluded collection or note exists. A serialized mutation plan can also lie about the actor or authorization used during planning. The library cannot authenticate arbitrary caller strings, while the local CLI's actual security boundary is the operating system and local filesystem permissions.

## Decision drivers

- Opaque denial across trust boundaries
- Separation of authorship metadata from authenticated identity
- Compatibility with future external authenticators
- Exact, testable trust-domain behavior
- Local CLI usability without pretending to provide remote security

## Considered options

### Resolve first and filter

- Good: simple lookup flow.
- Bad: leaks target existence through errors and timing-visible branches.

### Trust actor and task strings in plans

- Good: minimal interface.
- Bad: confuses attribution with authentication and is forgeable.

### Authenticator-issued principals and authorization before lookup

- Good: makes identity provenance explicit and denial opaque.
- Good: supports local OS identity and later external authenticators.
- Bad: requires callers to carry policy and grant revisions through planning and apply.

## Decision outcome

The library accepts only internally sealed `AuthenticatedPrincipal` values issued by an authenticator boundary. The CLI creates a `LocalFilesystemPrincipal` from the current OS account. `actor` and `task` remain asserted authorship metadata and need not equal the OS principal. Collections without external policy still enforce the manifest mutation policy and local principal.

Cross-domain authorization uses owner-maintained catalog domain metadata before opening a target. Empty collection grants deny. Rules match exact source and destination domain sets, and projection enclaves also use exact sets. `repo://` locators require a named configured root; `file://` locators require an explicitly allowed root. Both enforce containment after symlink resolution. Manifest identity must match the catalog entry, and policy identity must match the manifest binding. Effective domains propagate transitively over canonical relations and provenance dependencies.

Manifest policy references are collection-contained. An external policy input is accepted only with its expected identifier and canonical digest. When both sources exist, their parsed policies must agree. Resolution first authorizes catalog-declared primary domains, then opens the target opaquely, recursively follows authorized canonical note/provenance dependencies, computes effective domains to a fixed point across cycles, and authorizes the complete set. Missing or unauthorized dependencies make the target opaquely unavailable. The result carries a digest over participating revisions and effective domains.

## Consequences

- Denied present and absent targets have the same observable resolution outcome.
- Plans cannot use asserted actor text as an authorization principal.
- Local CLI security remains limited to OS and filesystem controls.
- Catalog and policy revisions become decision inputs that invalidate stale plans.

## Confirmation

- Negative tests compare denial for present and absent targets.
- Tests cover unknown repo roots, file-root escape, symlink escape, manifest mismatch, policy mismatch, empty grants, exact-set rules, and transitive propagation.
- Tests cover cycles, changed dependency revisions, external-policy disagreement, and indistinguishable missing/unauthorized dependency findings.
- Apply re-evaluates the supplied principal, policy, and grant.

## References

- `src/knowledge_system/authentication.py`
- `src/knowledge_system/resolution.py`
- `src/knowledge_system/trust.py`
