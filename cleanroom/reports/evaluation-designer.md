# Clean-room evaluation design and untouched baseline

Date: 2026-08-05  
Source: upstream `develop` at `e2acd39fd9b77619b6ed9f0ee47828c04f9dfb40`  
Product changes: none

## Outcome

The standalone evaluator under `cleanroom/eval` contains 294 scenarios. It
invokes a real ICM binary through public CLI, stdio MCP, and HTTP surfaces
against evaluator-owned fixtures and loopback services.

After removing redundant evaluator self-checks and candidate-adjacent support
hooks, the retained untouched-baseline outcomes are:

| Status | Count |
|---|---:|
| PASS | 62 |
| FAIL | 21 |
| UNSUPPORTED_BASELINE | 211 |
| Total | 294 |

Candidate mode requires every scenario to pass. The 29 deterministic legacy
observations remain exact SHA-256 gates. Missing replacement capabilities are
accepted as baseline evidence only when a concrete wire response or nonzero
public-CLI probe is captured.

## Contract

The evaluator verifies five fixture checksums, seven contract checksums, the
complete unique scenario inventory, 31 legacy tools, 11 independently
self-contained structured-output schemas, 29 legacy goldens, and 13 typed
threshold bindings.

The four revision-sensitive boundary scenarios remain explicit:

- recall limits 0 and 101 preserve 2024 normalization but are rejected by the
  2026 closed input schema;
- an unknown recall field is ignored in 2024 and rejected in 2026;
- malformed resource URIs are probed through 2026 `resources/read`, where
  method-not-found proves only that the untouched baseline lacks the method.

Latency is recorded as five blocks of 20 samples after five warmups per
operation. It is reporting-only: no machine-specific baseline or absolute
cross-host latency gate affects acceptance. Retrieval and bounded payload,
resource, and wire-size checks remain acceptance gates.

## Isolation and evidence

The retained isolation scenarios cover fixture hashes, cleared synthetic child
environments, root containment, canary integrity and nondisclosure, exclusion
of inherited real-state inputs, loopback endpoints, bounded child cleanup, and
observable equality of a real candidate probe under spaces and Unicode roots.
The `self-test` command also runs the complete suite under both roots and
requires byte-identical normalized reports.

Candidate, suite, work, and evidence roots are resolved before use, must be pairwise
disjoint strict children of the explicit workspace, and may not overlap real
user-state roots. Every scenario gets a fresh synthetic home, XDG tree,
Windows profile/app-data tree, temp tree, database, configuration, cwd, and
cleared child environment. Candidate arguments, environment, cwd, captures,
and artifacts are checked for inherited real-state paths. Canary bytes are
kept outside the scenario root and checked after every scenario.

All candidate and evaluator-owned child processes use timeout-bounded guards
that kill and reap on drop. Configured endpoints and recorded peer/local
sockets must be loopback. The evaluator-owned HTTP mock retains bounded request
bodies, deterministic responses, and cleanup checks.

## Public-surface coverage

Provider coverage uses 95 black-box cases across Codex, Claude Code, Cursor,
OpenCode, and Zed in project-local and user scopes. It checks exact public CLI
plans, real configuration paths, semantic file readback, ownership manifests,
fail-closed malformed/ambiguous inputs, preservation of unrelated bytes, and
owned-value-only removal. Candidate-adjacent provider-engine journals and the
nonportable reparse support case are not acceptance evidence.

Proxy coverage uses 41 public-surface scenarios. The evaluator-owned loopback
mock records raw requests, responses, headers, peer/local sockets, and process
topology. Three real-daemon scenarios exercise public `serve --http` plus
public proxy MCP tools/list, tools/call, and bounded cleanup without consuming
candidate-emitted evaluator journals or construction counters.

Resource coverage uses 36 public MCP scenarios for the fixed URI, exact DTO,
topic/project selection, deterministic ordering, byte/row/field limits,
read-only behavior, escaping, cache policy, and sanitized failures. The former
snapshot barrier scenario was removed because it required a sibling support
binary rather than public candidate behavior.

## Baseline distribution

| Area | Total | PASS | FAIL | UNSUPPORTED_BASELINE |
|---|---:|---:|---:|---:|
| Isolation | 8 | 8 | 0 | 0 |
| Legacy MCP | 32 | 32 | 0 | 0 |
| Modern MCP | 57 | 1 | 17 | 39 |
| Resources | 36 | 0 | 0 | 36 |
| Provider black box | 95 | 0 | 0 | 95 |
| Proxy/daemon | 41 | 1 | 0 | 40 |
| Boundaries | 22 | 17 | 4 | 1 |
| Metrics | 3 | 3 | 0 | 0 |

The 21 retained failures are six lifecycle-state violations, eleven modern
tools/list or annotation violations, and four input-boundary deficiencies.
All other absent replacement surfaces remain explicit unsupported baseline
evidence and become failures in candidate mode.
