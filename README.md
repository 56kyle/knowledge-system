# Knowledge System

Knowledge System is a local foundation for human-owned, agent-assisted Markdown collections. Markdown is the durable authority. The package inspects and validates collections, resolves stable references, evaluates FLAP and research profiles, computes trust-domain propagation, and applies reviewed changes through compare-and-swap mutation plans.

The package does not provide a database, embedding index, RAG service, MCP server, Obsidian plugin, or credential store. Projection records are contracts for later derived systems; they are not a second authority.

## Install

The repository uses `uv`:

```console
uv sync --all-groups
uv run kn --help
```

Runtime dependencies are Pydantic, ruamel.yaml, Typer, Loguru, Platformdirs, and typing-extensions.

## Collection basics

A managed collection can contain `collection.yaml`, `profiles.lock.yaml`, and `retired-ids.yaml`. A directory without a manifest is still inspectable as generic Markdown, but its notes do not gain durable collection identity or profile semantics.

Registered notes use readable, collection-scoped identities:

```yaml
---
id: stable-identities-survive-moves
profiles: [research@1]
created_by: human:kyle
origin: human
review:
  status: unreviewed
research_kind: concept
research_depth: studied
sources: [source-version:identity-paper/v1]
---
```

Canonical references use `note:<collection>/<id>` and optional block selectors such as `note:architecture/stable-identities-survive-moves#^claim`.

## Safe local changes

`kn register` and `kn mutation plan` produce an immutable plan before writing. `kn mutation apply` treats serialized plans as hostile: it verifies the plan digest, collection snapshot, authorization inputs, file hashes, identity reservations, semantic results, and an optional Git revision before any write. The CLI authenticates the current OS account as its local-filesystem principal; `actor` and `task` remain independent attribution. A stale precondition exits with code `3` and performs no writes.

<!-- github-only -->

See [usage](docs/usage.md), [reference](docs/reference.md), and [design decisions](docs/decisions/) for the complete local-core contract.
