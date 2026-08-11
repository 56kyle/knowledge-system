# 0005 - Use hostile-input-safe compare-and-swap mutation plans

## Status

Accepted

## Context and problem statement

Many agents can propose changes while a human edits a Git-backed collection. Direct writes can overwrite work. A saved plan crosses a serialization boundary and is therefore hostile input: its paths, hashes, authorization claims, proposed bytes, reservations, and readable diff can all be altered. Atomic replacement of one file does not make a multi-file operation crash-atomic.

## Decision drivers

- Human-reviewable intent and diffs
- Zero-write failure for every detectable stale or invalid plan
- No path or symlink escape
- Complete binding of decision inputs
- Identity uniqueness across active and retired records
- Honest recovery semantics for multi-file failure

## Considered options

### Direct writes

- Good: minimal machinery.
- Bad: no preview, weak concurrency control, and unsafe agent authority.

### Append-only event log as authority

- Good: provides an auditable sequence.
- Bad: makes Markdown a projection instead of durable authority.

### Immutable plan plus full preflight and compare-and-swap apply

- Good: separates proposal, review, and effects.
- Good: detects stale files and decision inputs before writes.
- Bad: plans are larger and multi-file crash atomicity is still unavailable.

## Decision outcome

Separate typed intent, planning, and apply. Store planned file paths as normalized collection-relative POSIX paths. Reject empty, absolute, drive-qualified, device, UNC, dot-segment, traversal, and symlink-escaping paths. A plan carries collection identity, root identity, intent payload, actor/task attribution, semantic unit, optional Git revision, every file precondition and proposed byte hash, typed identity reservations, and digests for the collection snapshot, manifest, profile locks and definitions, vocabulary, catalog, policy, grant, and locally resolved decision targets.

Compute `plan_sha256` from every security-relevant field except itself and the non-authoritative rendered diff. Recompute it before path-derived I/O. Preflight requires unique paths and an exact planned-file/precondition bijection, validates internal existence and hash consistency, rescans active and retired identities, checks Git and all input revisions, decodes and hashes all proposed bytes, parses all Markdown and YAML, runs semantic validation, and evaluates authorization before creating backups or writing. Ignore serialized diff text as an authority.

Apply uses same-directory temporary files and atomic replacement per file. It performs best-effort rollback if a later write fails. It does not claim cross-file crash atomicity. A rollback that cannot be proved raises `ApplyIndeterminateError` and requires human recovery.

Apply exclusively creates `.knowledge-system/collection.lock` before preflight and holds it through final verification or rollback. A provably dead same-host lock older than five minutes is recoverable; unknown ownership requires `--recover-lock` plus an in-process owner approval. Release is nonce checked. On Windows, portable Python cannot retain directory handles with delete-sharing semantics, so apply records device/inode identities for every existing parent, rejects symlink/reparse components, and rechecks identities before backup and every write/delete. This assumes the collection ACL prevents an untrusted principal from replacing the collection root itself; any unverifiable identity fails closed.

Automatic same-host dead-PID recovery is POSIX-only because Windows `os.kill(pid, 0)` cannot reliably prove PID absence; Windows locks are therefore unverifiable and require authenticated local-owner `--recover-lock` approval bound to the operation, action, plan digest, snapshot, and policy. Machine matching uses `platform.node()` with `socket.gethostname()` as a fallback; an unknown identity never auto-recovers.

Direct operations require the current authenticated local principal. Review-tier operations additionally require an in-process `MutationApproval` bound to principal, plan, snapshot, and policy. Explicit-authorization operations also require the action grant. Plan output uses exclusive regular-file creation, flush, and filesystem sync; output collisions fail and `--stdout` cannot be combined with apply.

Supported intents remain registration, Markdown creation, tags/aliases changes, one selected tags/aliases subtree replacement, identity-preserving move, collection-ID reservation, and atomic note retirement plus ledger append. Retirement never deletes a note and records disposition, date, and optional canonical successor.

## Consequences

- Detectable conflicts return before any write.
- Saved plans are portable review artifacts but not bearer authorization.
- Large collections incur snapshot and preflight scan cost.
- Cross-file failure may require explicit recovery despite rollback attempts.

## Confirmation

- Tests tamper every plan field, path, Base64 payload, hash, reservation, policy/grant input, and diff.
- Tests prove stale-file, Git, configuration, catalog, policy, and identity conflicts write zero bytes.
- Tests cover nested destination creation, CRLF preservation, retirement-ledger creation, rollback, and symlink escape.
- Tests cover competing processes, nonce-safe release, stale/unknown recovery, reparse substitution, parent identity changes, approval tiers, and exclusive plan-output collisions.
- Read-only and failed-apply tests compare bytes and modification times.

## References

- `src/knowledge_system/mutation.py`
- `src/knowledge_system/domain.py`
- ADR 0004 for principal ownership and authorization
