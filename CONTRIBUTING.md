# Contributing to ICM

**Welcome!** We appreciate your interest in contributing to ICM.

## Quick Links

- [Report an Issue](../../issues/new)
- [Open Pull Requests](../../pulls)
- [Start a Discussion](../../discussions)

---

## What is ICM?

**ICM (Infinite Context Memory)** is a persistent long-term memory for LLM agents, written in Rust. It stores memories with embeddings in SQLite, does hybrid retrieval (BM25/FTS5 + vector similarity), manages temporal decay and consolidation, and exposes an MCP server so tools like Claude Code, Codex, and others can store and recall memories across sessions.

---

## Ways to Contribute

| Type | Examples |
|------|----------|
| **Report** | File a clear issue with steps to reproduce, expected vs actual behavior |
| **Fix** | Bug fixes, correctness issues, durability/robustness improvements |
| **Build** | New features (for core features — storage backends, retrieval, MCP tools — discuss with maintainers first) |
| **Review** | Review open PRs, test changes locally, leave constructive feedback |
| **Document** | Improve docs, clarify behavior |

---

## Design Philosophy

A few principles guide ICM. Understanding them helps your contribution fit naturally.

### Correctness over cleverness

ICM is positioned as a durable, cross-host brain shared by multiple agents writing the same store concurrently. Data loss and silent corruption are the worst failure modes. Prefer the safe, boring path; back up before destructive operations; never claim a fix you can't verify.

### No panics in production code

No `.unwrap()` / `.expect()` / `panic!` in non-test code. Use typed errors (`thiserror`) in libraries and `anyhow` with `.context()` at the CLI boundary, and propagate with `?`. A hook or MCP tool must degrade gracefully, never crash the caller.

### Async-first I/O, cheap hot paths

All I/O is async where it matters. Keep the per-hook and per-prompt paths cheap — they run on every tool call. Don't load heavy models or do network I/O on a path that must return in milliseconds.

### Backends are additive, selected at runtime

SQLite is the default in-process backend; Postgres/OpenSearch are compiled in and chosen at runtime via `ICM_DB_BACKEND`. New storage features should respect this split and not assume SQLite.

### Extensibility

Reuse existing components and traits (`MemoryStore`, `Embedder`, …) instead of duplicating. New core features (backends, retrievers, MCP tools) are worth discussing before you build.

---

## Commit Messages & Changelog

ICM uses [Conventional Commits](https://www.conventionalcommits.org/) and [release-please](https://github.com/googleapis/release-please) to **auto-generate CHANGELOG.md, version bumps, and GitHub releases**. Never edit `CHANGELOG.md` manually — it is fully managed by release-please from your commit messages.

### Commit format

```
<type>(<scope>): <short description>
```

| Type | Semver Impact | When to Use |
|------|---------------|-------------|
| `feat` | Minor | New features, new MCP tools, new backends |
| `fix` | Patch | Bug fixes, corrections |
| `perf` | Patch | Performance improvements |
| `refactor` | — | Code restructuring (no changelog entry) |
| `docs` | — | Documentation only |
| `chore` | — | Maintenance, CI, deps |
| `feat!` / `fix!` | Major | Breaking changes (add `!` after type) |

**Scope** should match the module or area: `store`, `mcp`, `retriever`, `hooks`, `cli`, `cicd`, etc.

### Examples

```
feat(mcp): add icm_memory_health tool
fix(store): open read-only connections WAL-aware instead of immutable
perf(retriever): reuse the FTS statement across recall calls
feat!(store): change the embedding column layout
```

These commit messages become CHANGELOG entries when release-please cuts a release. Write them as if users will read them.

---

## Branch Naming Convention

Git branch names cannot include spaces or colons, so we use slash-prefixed names.

| Prefix | When to Use |
|--------|-------------|
| `fix/` | Bug fixes, corrections, minor adjustments |
| `feat/` | New features |
| `chore/` | CI/CD, deps, maintenance, breaking changes |

Combine the prefix with a scope if it adds clarity and finish with a short, kebab-case slug:

```
fix/store-readonly-live-connection
feat/mcp-http-proxy-mode
chore/release-pipeline-cleanup
```

---

## Pull Request Process

### Scope Rules

**Each PR must focus on a single feature, fix, or change.** The diff must stay in-scope with the PR title and body. Out-of-scope changes (unrelated refactors, drive-by fixes, formatting of untouched files) go in a separate PR. For large features, prefer several logical, independently-reviewable PRs over one enormous one.

### 1. Create your branch

```bash
git checkout develop
git pull origin develop
git checkout -b feat/scope-your-clear-description
```

### 2. Make your changes

Respect the existing workspace layout (`crates/icm-*`). Keep functions short and focused. Comments explain *why*, not *what*.

### 3. Add tests

Every change **must** include tests where it has a runtime surface. See [Testing](#testing).

### 4. Add documentation

Update docs for new features and changes to already-documented behavior.

### 5. Target `develop`

Open your Pull Request against the **`develop`** branch. `main` is reserved for stable releases — only maintainer `develop` → `main` PRs (cut via release-please) target it.

### 6. Review & CI

1. **Maintainer review** — a maintainer reviews for quality and alignment.
2. **CI/CD checks** — automated tests and lints must pass.
3. **Resolution** — address feedback from review or CI.

### 7. Integration & release

```
your branch --> develop (review + CI + integration) --> main (versioned release via release-please)
```

---

## Testing

### Pre-Commit Gate (mandatory)

All three must pass before any PR:

```bash
cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

### PR Testing Checklist

- [ ] Unit tests added/updated for changed code
- [ ] Integration/e2e coverage where the change has a runtime surface
- [ ] No `.unwrap()` / `.expect()` / `panic!` in non-test code
- [ ] `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace` passes
- [ ] Manual test: exercise the affected flow (CLI command, MCP tool, hook) and inspect the result

---

## MCP evaluator changes

Changes to MCP behavior should be exercised through the workspace evaluator
when applicable. Keep synthetic fixtures, frozen contracts/goldens,
normalization, metrics, and isolation assertions in `crates/icm-mcp-eval`;
do not reimplement production protocol, framing, dispatch, or schemas there.
Ordinary MCP scenarios use the production `icm-mcp` service in-process, while
CLI, provider, proxy, HTTP, transport-edge, and process-isolation scenarios
must remain candidate-process tests.

Before opening a PR that changes the evaluator or MCP service, run:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --locked --offline -p icm-mcp-eval
cargo run -p icm-mcp-eval --locked --offline -- verify-design \
  --suite-root crates/icm-mcp-eval
```

Use a dedicated non-Git workspace for the two-root self-test. Never use real
user state, credentials, provider configuration, network services, or a fixed
port. See the evaluator README for candidate build and staging instructions.

## Questions?

- **Bug reports & features**: [Issues](../../issues)
- **Discussions**: [GitHub Discussions](../../discussions)

**For external contributors**: your PR undergoes automated and manual security review (see [SECURITY.md](SECURITY.md)).

---

**Thank you for contributing to ICM!**
