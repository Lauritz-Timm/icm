# Clean-room evaluation design v7 and untouched baseline

Date: 2026-08-05  
Role: independent evaluation designer  
Source: upstream `develop` at `e2acd39fd9b77619b6ed9f0ee47828c04f9dfb40`  
Product changes: none

## Outcome

The standalone evaluator under `cleanroom/eval` now implements the audited v7
design. It contains 326 preregistered scenarios and evaluates a real ICM binary
against evaluator-owned SQLite/JSON fixtures, 29 exact legacy observations,
closed modern schemas, provider lifecycle contracts, and deterministic
loopback proxy/daemon integrations.

The corrected authoritative untouched-develop result is:

| Status | Count | Meaning |
|---|---:|---|
| PASS | 70 | Untouched behavior met the preregistered contract |
| FAIL | 21 | Reproducible upstream protocol or boundary deficiencies |
| UNSUPPORTED_BASELINE | 235 | Required replacement capability is absent, with concrete wire or CLI evidence |
| Total | 326 | Complete v7 inventory |

`portableAcceptance` is false for untouched `develop`, as expected. Candidate
mode requires every scenario to pass. Replaying the untouched binary in
candidate mode produced 70 PASS and 256 FAIL: the 21 observed deficiencies and
all 235 unsupported capabilities became hard failures. All 70 baseline passes
remained passes, including all 29 exact deterministic legacy goldens.

Versions 1 through 4 were frozen before replacement code. Phase 2 replacement
source existed while v5 was corrected, so v5 does not make that blanket claim.
Version 5 was frozen before any candidate scenario execution, no candidate
outcomes were observed or used to tune acceptance, and its correction basis was
limited to official MCP output-schema semantics and independently mergeable
phase gates. Version 6 was derived only from the official final MCP basic/schema
and v1-v5 preregistration provenance: that audit inspected neither Phase 2
source nor candidate outcomes and changed neither inventory nor thresholds.

Phase 2 results existed and were compared for the bounded v7 correction. That
comparison isolated the two limit scenarios whose v5/v6 outcomes changed while
their candidate hashes differed; it was not used to select an expected product
outcome. Version 7 inspected and changed only evaluator contracts, source,
reports, and untouched-develop evidence. It did not inspect Phase 2 product
source or execute the Phase 2 candidate. The correction basis was the
evaluator's hardcoded legacy initialization for revision-sensitive boundary
probes, the already-frozen legacy/modern architecture, and untouched-develop
wire evidence. Inventory and thresholds remain unchanged. All authoritative
evaluator-freeze evidence below evaluates the unchanged upstream-develop
binary, not the Phase 2 product.

## Provenance and package health

The evaluated ICM binary has SHA-256
`8ec3c43899f6f899c230165026945b224ad9926f41ae6d618c6d473ad032e684`.
The final evaluator binary has SHA-256
`a1ed404646d3522bfe55b69ce26f5dace388c66d4bf82928d8d43346197215b5`.
The v7 preregistered design has SHA-256
`632cc2658e5eec88f1c0c0bf17eab1f47e8b058234dc19bf1f3da4f212230f1b`.
The evaluator source-tree aggregate, computed from the sorted
`Cargo.toml`/`Cargo.lock`/`src`/`contracts`/`fixtures`/`goldens` file-hash list
relative to the evaluator root, is
`91a822ea882f6d2623e1622b64c5eaa3d5261af85a188bcdda53a6be96db5d54`.
Its independent lockfile has SHA-256
`5c620c2c8f895a15524e8b4589246f72e9af67f59a3157f9c681d51380ac4993`.

The v7-specific implementation hashes are:

| File | SHA-256 |
|---|---|
| `src/design.rs` | `88e1b1d9d81b6b5e85e27c9ddd78ee5acacd10105370c84e6bb514d0450ea246` |
| `src/evaluate.rs` | `c87e661d2fc2897099497a1afb3e81ea4f23fad3bf068bfa5fe5bb470472b817` |
| `src/fixtures.rs` | `2f584505e536eff1aa41718fb26753f2f0130902be0091ac99331f0ece0e8959` |
| `src/mcp.rs` | `8b45286f12752900dd167313c59c9e5c7198155a50a15905bf590573dc1b7db7` |
| `src/schema.rs` | `94650877e0fd26b547c5df095a0f02506bfe9b3e5f3c4649fc764c84b95a8f4b` |
| `contracts/checksums.sha256` | `bf835498b7b0533e1e9eed27a7a97d30b90771cab0b3eb3a1342e2c1b0bf3787` |

The final evaluator passes:

- `cargo fmt --check`;
- locked, offline build and tests;
- locked, offline clippy across all targets with warnings denied;
- 34 evaluator-owned unit tests;
- design verification at version 7: 326 scenarios, 31 tools, 11 structured
  tool schemas, 29 deterministic legacy goldens, five fixture files, seven
  contract files, and 30 typed threshold bindings;
- a real-loopback, two-root self-test under one spaces path and one Unicode
  path, with byte-identical normalized reports.

The evaluator is standalone: its fixture constructor compiles no product
crate and directly creates the synthetic database from the frozen SQL schema
and JSON fixtures. Product behavior is observed only by launching the separate
candidate binary. No product source, repository lockfile, branch, commit, or
remote was changed.

## Frozen v7 contract

Versions 1 through 6 remain immutable in their prior evidence and archives.
Version 7 corrects four boundary scenarios without changing their IDs, the
326-scenario inventory, or any of the 30 typed thresholds:

- `boundary.limit-under` and `boundary.limit-over` each launch separate 2024
  and 2026 candidate processes. A deterministic 101-row matching fixture makes
  the legacy observations exact: limit 0 returns one row and limit 101 returns
  20 rows. The modern leg must reject either value with `-32602`;
- `boundary.unknown-field` uses separate candidate processes. Its 2024 recall
  leg must ignore the extra argument and return exactly one result, while its
  2026 closed-schema leg must reject the same argument with `-32602`;
- `boundary.malformed-uri` is a modern `resources/read` request. Only
  `-32602` proves URI validation; `-32601` proves that the baseline lacks the
  method and is classified `UNSUPPORTED_BASELINE`, never PASS;
- every supported leg records `legPassed`, and raw evidence carries explicit
  `#legacy-2024` and `#modern-2026` labels so no aggregate scenario status can
  hide which revision was exercised.

Version 6's bounded lifecycle/metadata corrections remain in force:

- ICM's new application-defined era-lock and lifecycle errors are `-31010` and
  `-31011`, outside the final specification's `-32768..-32000` reserved range;
  the former `-32010`/`-32011` meanings were introduced in v4 and therefore
  were not eligible for the legacy-code carve-out;
- `modern.2026-invalid-meta-key` sends `1bad/foo`, whose prefix label starts
  with a digit. Bare `invalid` is retained as a positive grammar regression
  because an unprefixed alphanumeric name is valid;
- top-level `_meta` is not claimed to be independently forbidden; it simply
  does not satisfy the required metadata at `params._meta`;
- one era per stdio process is an explicit ICM compatibility policy, not an
  MCP-mandated error behavior. MCP permits but does not require concurrent
  dual-era service; every 2026 request remains stateless and is validated from
  its own metadata;
- the scenario inventory and acceptance thresholds remain unchanged.

Version 5's independent-schema and phase-independence corrections remain in
force:

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
- the ICM stdio compatibility era is locked to application error `-31010`
  with its exact message/data contract, while lifecycle misuse is separately
  locked to application error `-31011`;
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
| `mcp-2026-wire-contract.json` | `81fa75b803be52499befe18e7cb7e4f1ae78d4d2b110d54254a91dace12a60d4` |
| `modern-output-schemas.json` | `640f018bab821ad1d81e3c10fa6c986eabc460fd763d2dc9a54539a88f0bee9c` |
| `normalization-rules.json` | `d2f012a84b713fed7a364368c7453df70f0f2dbf53eb313b20f2c1ddb39e8245` |
| `preregistered-design.json` | `632cc2658e5eec88f1c0c0bf17eab1f47e8b058234dc19bf1f3da4f212230f1b` |
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

## Authoritative v7 evidence

The spaces/Unicode two-root reports are byte-identical after only the frozen
normalization allowlist:

`e2d8c377f05ebfea9a40a95f5a46afa34541ba43b8ef6002320f752a80f815f3`

Artifacts relative to the v7 evidence root:

| Artifact | SHA-256 |
|---|---|
| `authoritative-untouched-develop-v7-result.json` | `c833cc9f266e911d93ec9d428b8783b205f6da136ff3c690c198758602544b8c` |
| `authoritative-untouched-develop-v7-raw-exchanges.jsonl` | `b111c0fdd5b9993a5630668c934648b81680813321f4c985f00d2350acf8cd19` |
| `authoritative-hermetic-two-root-v7-result.json` | `dc1841dd395f4123f7eeea5ac163cf50e8afde776cd23d2930e44422a37243cc` |
| `authoritative-hermetic-two-root-v7-root-1-result.json` | `1e932ab77425f9e7c7c3d342bfc23f785d8c8354adbcc192434b6149d96e6ff5` |
| `authoritative-hermetic-two-root-v7-root-1-raw-exchanges.jsonl` | `fae6c7103f78483ca82f4f5a97d8eb301383057f87e7746ae1ddfbea3e23c440` |
| `authoritative-hermetic-two-root-v7-root-2-result.json` | `baca565ec6177b9afb3cf97f758b24ae2bc4a79adbaa6089c552bdcd32afc836` |
| `authoritative-hermetic-two-root-v7-root-2-raw-exchanges.jsonl` | `b72b7f43dc74a2a36b3dbcbbd522ea64321086d18cab50acf73947db99a8ed0c` |
| `authoritative-golden-replay-v7-result.json` | `abb9a571dd39152ba8506720ad65e487e49488a55428bebf0b5cd4d00a90f3ad` |
| `authoritative-golden-replay-v7-raw-exchanges.jsonl` | `3155fdacb3189246b6a257eda4fa627a70911c233def7dc660102670b645f982` |

The aggregate over the lexicographically ordered nine-file `sha256sum` output
is `2a40188274847691dd089612a96e31c885962baeeafe2d3374aff3fef7656e56`.

## Baseline measurements

The named baseline preserved legacy payload wire sizes: tools/list 13,922
bytes, memory recall 331, and memory stats 170. Five blocks of 20 measured
samples produced these host observations in microseconds:

| Operation | Median | p95 |
|---|---:|---:|
| tools/list | 1,450 | 1,730 |
| memory/recall | 1,387 | 1,589 |
| memory/stats | 101 | 126 |

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
| Boundaries | 22 | 17 | 4 | 1 |
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
18. the modern leg of `boundary.unknown-field` accepts an unrecognized recall
    argument instead of returning `-32602`;
19. the modern leg of `boundary.limit-under` accepts/clamps recall limit 0
    instead of returning `-32602`;
20. the modern leg of `boundary.limit-over` accepts/clamps recall limit 101
    instead of returning `-32602`;
21. the legacy `boundary.path-traversal` probe accepts `../` inside the
    synthetic probe tree.

The corresponding 2024 legs for unknown-field and both limit scenarios pass:
the extra recall argument is ignored with one result, and limits 0 and 101
produce exactly one and 20 results. The malformed-URI scenario is not among
the failures: its modern `resources/read` probe returned `-32601`, concrete
evidence that the baseline lacks the method but no evidence of URI validation.

The 235 unsupported statuses comprise 38 modern, 37 resource, 115 provider,
44 proxy/daemon, and one boundary scenario. Each carries its own concrete CLI
or wire proof.

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
