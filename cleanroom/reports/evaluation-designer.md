# Clean-room evaluation design v5 and untouched baseline

Date: 2026-08-05  
Role: independent evaluation designer  
Source: upstream `develop` at `e2acd39fd9b77619b6ed9f0ee47828c04f9dfb40`  
Product changes: none

## Outcome

The standalone evaluator under `cleanroom/eval` now implements the audited v5
design. It contains 326 preregistered scenarios and evaluates a real ICM binary
against evaluator-owned SQLite/JSON fixtures, 29 exact legacy observations,
closed modern schemas, provider lifecycle contracts, and deterministic
loopback proxy/daemon integrations.

The corrected authoritative untouched-develop result is:

| Status | Count | Meaning |
|---|---:|---|
| PASS | 71 | Untouched behavior met the preregistered contract |
| FAIL | 21 | Reproducible upstream protocol or boundary deficiencies |
| UNSUPPORTED_BASELINE | 234 | Required replacement capability is absent, with concrete wire or CLI evidence |
| Total | 326 | Complete v5 inventory |

`portableAcceptance` is false for untouched `develop`, as expected. Candidate
mode requires every scenario to pass. Replaying the untouched binary in
candidate mode produced 71 PASS and 255 FAIL: the 21 observed deficiencies and
all 234 unsupported capabilities became hard failures. All 71 baseline passes
remained passes, including all 29 exact deterministic legacy goldens.

Versions 1 through 4 were frozen before replacement code. Phase 2 replacement
source existed while v5 was corrected, so v5 does not make that blanket claim.
Version 5 was frozen before any candidate scenario execution, no candidate
outcomes were observed or used to tune acceptance, and its correction basis was
limited to official MCP output-schema semantics and independently mergeable
phase gates. All authoritative evaluator-freeze evidence below evaluates the
unchanged upstream-develop binary, not the changing Phase 2 product.

## Provenance and package health

The evaluated ICM binary has SHA-256
`8ec3c43899f6f899c230165026945b224ad9926f41ae6d618c6d473ad032e684`.
The final evaluator binary has SHA-256
`82c5c0893174b03b8ed9e396c5e3580cb629b718eb0cf25914a3899a71183cd5`.
The v5 preregistered design has SHA-256
`103e7e34ef7c475d03d0be34a2c6e1a51d4813008fe3a0a6390a815f56609c63`.
The evaluator source-tree aggregate, computed from the sorted
`Cargo.toml`/`Cargo.lock`/`src`/`contracts`/`fixtures`/`goldens` file-hash list,
is `9aa3f35add0fd37df906752a87d9d4e676133d917278f7fb79a26a925f5a6528`.
Its independent lockfile has SHA-256
`5c620c2c8f895a15524e8b4589246f72e9af67f59a3157f9c681d51380ac4993`.

The final evaluator passes:

- `cargo fmt --check`;
- locked, offline build and tests;
- locked, offline clippy across all targets with warnings denied;
- 31 evaluator-owned unit tests;
- design verification at version 5: 326 scenarios, 31 tools, 11 structured
  tool schemas, 29 deterministic legacy goldens, five fixture files, seven
  contract files, and 30 typed threshold bindings;
- a real-loopback, two-root self-test under one spaces path and one Unicode
  path, with byte-identical normalized reports.

The evaluator is standalone: its fixture constructor compiles no product
crate and directly creates the synthetic database from the frozen SQL schema
and JSON fixtures. Product behavior is observed only by launching the separate
candidate binary. No product source, repository lockfile, branch, commit, or
remote was changed.

## Frozen v5 contract

Versions 1 through 4 remain immutable in their prior evidence and archives.
Version 5 corrects two evaluator-integrity defects before candidate execution,
without changing the 326-scenario inventory or acceptance thresholds:

- each of the 11 advertised output schemas is independently self-contained,
  explicitly declares an object root for MCP 2025 projections, and resolves
  local references only against its own wire document; feedback record is
  inlined at its object root;
- actual structured emissions use the individual advertised schema as both
  resolver root and validation schema;
- output-schema presence, self-containment, and exact equality are mandatory
  only in the dedicated Phase 3 output-schema scenario. The ten Phase 2
  tools/list and annotation gates accept conforming responses without
  `outputSchema`; the closed-schema gate checks output closure only when an
  output schema is present;
- an evaluator regression runs all ten Phase 2 gates without output schemas and
  separately proves that the dedicated Phase 3 gate rejects their absence;

- exact MCP lifecycle state tests cover calls before initialize, the
  initialize-response gap, initialized-before-initialize, duplicate
  `notifications/initialized`, a second initialize, and a complete 2024
  lifecycle;
- the 2026-07-28 era is locked to JSON-RPC error `-32010` with its exact
  message/data contract, while lifecycle misuse is separately locked to
  `-32011`;
- modern requests use the full reserved metadata keys, exact result typing,
  cache metadata, closed output schemas, and actual-emission validation;
- resource selection freezes exact topic eligibility, ranking, tie-breaking,
  byte/token/row/field bounds, JSON escaping, and snapshot consistency;
- provider evaluation freezes exact CLI paths and scope flags, plan schemas,
  multi-document semantic edits, ownership boundaries, manifest behavior,
  ambiguity/unknown-dialect rejection, rollback, orphan cleanup, and
  evaluator-verified journals;
- proxy evaluation freezes the production CLI surface, MCP headers, token
  sources, loopback-only endpoint policy, response framing, session reuse,
  notification behavior, no-retry semantics, SSRF/rebinding defenses, process
  cleanup, and actual candidate-daemon topology;
- normalization is an exact JSON-pointer allowlist. Unknown same-named keys and
  shape drift survive and therefore break determinism rather than being
  recursively erased;
- `UNSUPPORTED_BASELINE` is accepted only with concrete nonzero CLI or wire
  evidence bound to the scenario.

The frozen contract hashes are:

| Contract | SHA-256 |
|---|---|
| `mcp-2026-wire-contract.json` | `266d433ded7fcb0a807c5faae313fa32da4c0d42bdf403fa19544ccba4752582` |
| `modern-output-schemas.json` | `640f018bab821ad1d81e3c10fa6c986eabc460fd763d2dc9a54539a88f0bee9c` |
| `normalization-rules.json` | `d2f012a84b713fed7a364368c7453df70f0f2dbf53eb313b20f2c1ddb39e8245` |
| `preregistered-design.json` | `103e7e34ef7c475d03d0be34a2c6e1a51d4813008fe3a0a6390a815f56609c63` |
| `provider-contracts.json` | `e4e51d09f0ac5ec3fe9e9ae02a254c86c6f38f61c3271a77ff7dbe61c2cf7a37` |
| `proxy-contracts.json` | `77c3ec5e536c9a1dc3538eeb7b3274929e16d4d58a62aa5238dce57d1828840e` |
| `tool-annotations.json` | `a09b9be52596d9c1c4de061f6a424bda556550122c6557a96c02279688dbf7ff` |

## Provider safety matrix

The provider inventory contains 100 black-box provider scenarios plus 15
evaluator-support integrity scenarios. It covers Codex, Claude Code, Cursor,
OpenCode, and Zed in both `project-local` and `user` scopes.

The exact production lifecycle surface is
`provider trust|strip|doctor --provider <id> --scope <scope>`, with `--yes`
where confirmation is required. Top-level `uninstall --yes --no-backup`
remains distinct and must delegate through the same lifecycle engine. Every
provider is exercised through `doctor`, and the exact-path/scope case runs
doctor in both scopes.

Fixtures model the real JSON, JSONC, and TOML document sets, including multiple
recognized documents. The evaluator independently seeds and hashes every
file, parses the candidate's raw plan, requires absolute contained paths,
validates semantic readback, verifies journal order and hashes, and checks the
final manifest. Candidate-reported booleans are never treated as proof.

Platform mapping is frozen for Linux, macOS, and Windows. Codex honors
`CODEX_HOME`; Claude honors `CLAUDE_CONFIG_DIR`; other providers use their
synthetic platform roots. Unix uses contained symlink adversaries. Windows
uses reparse/junction evidence without requiring privileged symlink creation.
The portable host execution was Linux; this report does not claim native
Windows or macOS CI execution.

Adversarial cases include an equal external entry, normalization collisions,
shadowed alternate scope entries, same-scope recognized-candidate ambiguity,
unknown/mixed dialects, concurrent mutation, partial failure rollback, and
orphan cleanup. No production hidden failpoint or environment switch is part
of the design; inaccessible pause/counter hooks live only in the sibling
evaluation-support binary, and the evaluator verifies their journals and
artifacts independently.

## Proxy and daemon integrity

The exact client surface is
`proxy --url <base-url> [--compact] [--token-file <path>]`, with optional
`ICM_PROXY_TOKEN`; inline token arguments are forbidden. The evaluator-owned
mock records raw requests, peer/local sockets, authorization, method, target,
headers, and body. Successful modern calls require the exact negotiated MCP
protocol version, method, client name, content type, Host/Origin policy, and
legacy session reuse where applicable.

The adversarial response inventory covers redirects, wrong MIME, oversized
frames, invalid UTF-8, SSE, truncation, timeout, response-ID mismatch,
hop-by-hop headers, one-shot 503/no retry, daemon disappearance, poisoned
ambient proxy variables, credential redaction, IPv4/IPv6 loopback, and DNS
rebinding. Notification tests use evaluator-owned readiness barriers rather
than timing guesses.

The four real-daemon scenarios launch the actual candidate's production HTTP
daemon, route the actual candidate proxy to it, exercise tools/list and
tools/call, and independently inspect the evaluator-built lifecycle journal
for one daemon and one store/model. Untouched `develop` lacks these CLI
surfaces, so the baseline records concrete unsupported CLI probes rather than
claiming successful topology.

## Resource integrity

The active-project resource contract freezes one URI,
`icm://active-project/context`, exact JSON keys, exact namespace eligibility,
deterministic importance/recency/ID ordering, and hard row, field, portable
token, and wire-byte limits. Bare-project, prefix-subtopic, suffix-alias,
global-error, oversized-first, and prompt-delimiter traps are committed
fixtures.

The snapshot scenario is evaluator-controlled. It obtains independent pre and
post responses, pauses only the inaccessible support read, commits an
evaluator-owned writer marker, then requires the candidate response to equal
one complete state rather than a mixed state. Journal ordering, hashes, raw
responses, and final database artifacts are verified independently.

## Isolation and nondisclosure hard gate

All 16 isolation scenarios passed in the named run and both self-test roots.
Suite, work, evidence, report, and archive roots are resolved before creation,
must be strict children of the explicit cleanroom workspace, and must be
pairwise disjoint where applicable. Inherited and default user-state roots are
rejected.

Every scenario receives a fresh synthetic home, XDG tree, Windows profile and
app-data tree, temp tree, database, configuration tree, cwd, and cleared child
environment. Candidate arguments, environment, and cwd are checked before
spawn. Captures are checked for real-state paths.

The deterministic 256-bit canary is outside each scenario root. Every created
sandbox is registered even if the scenario later fails. The evaluator checks
unchanged canary bytes and absence from stdout, stderr, raw exchanges, and all
regular scenario artifacts. Artifact symlinks are rejected without following
them. This proves integrity and nondisclosure on observed surfaces; it does
not claim detection of an arbitrary silent read.

Configured endpoints must parse as loopback. The named isolation probe
recorded one evaluator-owned integration request with peer and local IP both
`127.0.0.1`. It explicitly disclaims OS-firewall enforcement and arbitrary
socket observation. Child guards kill and reap on every drop path; the live
mock cleanup scenario proved listener closure after guard drop.

The authoritative evidence tree contains neither the inherited home path nor
the `ICM_EVAL_CANARY_V4_` prefix. Every result's embedded raw-exchange hash was
recomputed against its sibling JSONL file.

## Authoritative v5 evidence

The spaces/Unicode two-root reports are byte-identical after only the frozen
normalization allowlist:

`57a4aeb6c52bd3f483ee376ff5ff1f6625c712a8b0261d87d55df89557f470a1`

Artifacts relative to the v5 evidence root:

| Artifact | SHA-256 |
|---|---|
| `authoritative-untouched-develop-v5-result.json` | `b1da42793c7289c02b27cb6422b9da39d1375e765cffc1157ffe0ab96ff05cbb` |
| `authoritative-untouched-develop-v5-raw-exchanges.jsonl` | `5a1aa1e7bf59bb03672618a9cc71acec8e743b69de9eda1bc7604ce2cf459d8d` |
| `authoritative-hermetic-two-root-v5-result.json` | `77b6584e6083b0484df41c74e2a3dec476c4f15ed03e587f86c1f696c7b49b69` |
| `authoritative-hermetic-two-root-v5-root-1-result.json` | `98402e30c55560973cee16c2ed083ff62229ca3b8210de2f6fe281896137350d` |
| `authoritative-hermetic-two-root-v5-root-1-raw-exchanges.jsonl` | `cb32aae9fa2bd2dab3d32c1ad2cb3c5e618686675cfcd5141654c8e5b9cd08f3` |
| `authoritative-hermetic-two-root-v5-root-2-result.json` | `dbc53feafb8a1d42c9c185ec5f760497f549c56b7ab0e091bebaa5a03b7df138` |
| `authoritative-hermetic-two-root-v5-root-2-raw-exchanges.jsonl` | `a875f2cad3ffc86c7007902624a8f96aa6afffc6b4a480cc04589855b33f8f38` |
| `authoritative-golden-replay-v5-result.json` | `22aedeb0375bfa19f3ae17cd977316fc89dc230cc3c8a5ff30241fc14276084f` |
| `authoritative-golden-replay-v5-raw-exchanges.jsonl` | `b3fcefb1c63dfbdd5a7d5ee9c89d60d36c2b9041acb81e70b8b7f7cab753deac` |

The aggregate over the sorted nine-file evidence hash list is
`5f586b473e64471f71b063010ba4551a057ff4078373b252ba5f1c38bf78a03c`.

## Baseline measurements

The named baseline preserved legacy payload wire sizes: tools/list 13,922
bytes, memory recall 331, and memory stats 170. Five blocks of 20 measured
samples produced these host observations in microseconds:

| Operation | Median | p95 |
|---|---:|---:|
| tools/list | 1,460 | 1,688 |
| memory/recall | 1,480 | 1,643 |
| memory/stats | 129 | 142 |

Retrieval over six committed queries remained perfect: Hit@3 1.0, Recall@3
1.0, and nDCG@3 1.0. Latency is measured but interpreted with the frozen ratio,
allowance, and noise-floor rules; host PSS and real external models remain
supplemental and cannot affect portable acceptance.

## Untouched baseline gaps retained as gates

The baseline distribution by area is:

| Area | Total | PASS | FAIL | UNSUPPORTED_BASELINE |
|---|---:|---:|---:|---:|
| Isolation | 16 | 16 | 0 | 0 |
| Legacy MCP | 32 | 32 | 0 | 0 |
| Modern MCP | 56 | 1 | 17 | 38 |
| Resources | 37 | 0 | 0 | 37 |
| Provider black box | 100 | 0 | 0 | 100 |
| Provider engine integrity | 15 | 0 | 0 | 15 |
| Proxy/daemon | 45 | 1 | 0 | 44 |
| Boundaries | 22 | 18 | 4 | 0 |
| Metrics | 3 | 3 | 0 | 0 |

The 21 reproducible failures are six lifecycle-state violations, eleven
modern tools/list or annotation violations, and four retained input-boundary
deficiencies:

1. tools/list before initialize is accepted;
2. tools/call before initialize is accepted;
3. a request in the initialize-response gap is accepted;
4. duplicate initialized notification is accepted;
5. a second initialize with an era change is accepted;
6. initialized-before-initialize is accepted;
7. modern tools/list lacks the frozen 2026 result envelope/order;
8. modern tools/list lacks exact annotations;
9. modern tools/list lacks exact output schemas;
10. modern tools/list lacks cache metadata;
11. modern tools/list lacks required modern fields;
12. modern tools/list schemas are not closed as required;
13. memory-store destructive annotation is wrong or absent;
14. memory-recall destructive annotation is wrong or absent;
15. read-only annotation consistency is wrong or absent;
16. idempotence annotation consistency is wrong or absent;
17. the open-world learn-only annotation contract is wrong or absent;
18. `boundary.unknown-field` accepts an unrecognized store field;
19. `boundary.limit-under` silently accepts/clamps recall limit 0;
20. `boundary.limit-over` silently accepts/clamps recall limit 101;
21. `boundary.path-traversal` accepts `../` inside the synthetic probe tree.

The 234 unsupported statuses comprise 38 modern, 37 resource, 115 provider,
and 44 proxy/daemon scenarios. Each carries its own concrete CLI or wire proof.

## Replacement acceptance and archive

A replacement is acceptable only when all 326 scenarios PASS, all 29 legacy
observations remain exact, all 11 real structured emissions validate, provider
and proxy journals/artifacts validate independently, resource and payload caps
hold, retrieval and latency gates pass, process cleanup succeeds, and the
two-root normalized output remains identical.

Archive validation canonicalizes suite, evidence, report, and output before
creation and requires pairwise disjoint roots. The archive command refuses to
overwrite an existing package, excludes only evaluator build/run scratch, and
writes a SHA-256 manifest covering every copied evaluator, report, and evidence
file.
