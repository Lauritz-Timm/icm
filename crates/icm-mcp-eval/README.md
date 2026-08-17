# ICM clean-room evaluator

This package is an evaluation-first harness for the integrated MCP
implementation. It does not modify product code or inspect user state: fixture
data is synthetic and all scenario roots are temporary. Ordinary MCP scenarios
exercise `icm_mcp::McpService` directly; process-backed lanes retain a cleared
environment for isolation, proxy, and topology assertions.
The committed design is the contract; the runner invokes a real ICM
binary for process-backed lanes and records real wire responses,
synthetic-tree mutations, configured loopback HTTP integration traffic, and
process topology. A staged suite copy must include this package manifest,
contracts, fixtures, and goldens; normal workspace operation uses the crate
path directly. The frozen `productCratePathDependenciesAllowed: false` field
applies to fixture construction: SQL/JSON fixture generation remains free of
product crates. The workspace evaluator itself links only `icm-mcp` and
`icm-store` for its integrated service lane.

The initial design was frozen on 2026-08-05 before replacement implementation.
Later revisions are post-implementation audit/spec corrections. v9 was frozen
before the initial final-candidate run. That run exposed stale evaluator-only
provider journal and revision-sensitive proxy-header assumptions. v10 fixes
those assumptions and closes provider-state, Git-ancestry, and cross-scenario
canary gaps before the corrected candidate run. Its first two-root self-test
then exposed three stale modern text-ULID normalization rules; v11 removes
them because modern IDs live in `structuredContent` and concise text does not
duplicate them. Its completed two-root diff then identified the remaining
dynamic structured IDs and timestamps; v12 declares only those exact pointers.
The 294 scenarios and all thresholds remain unchanged.
The pre-implementation upstream observation remains frozen in
`goldens/baseline-metrics.json`, including its source commit and candidate
binary hash.

The required lane provides portable controlled-input isolation:

- every scenario receives a new synthetic home, XDG tree, Windows profile
  tree, database, configuration tree, working directory, and environment;
- the child environment is cleared and rebuilt from an explicit allowlist;
- embeddings are disabled for product behavior and the proxy topology lane
  uses a deterministic loopback mock daemon/model;
- no provider account, credential, real configuration, Git configuration,
  external service, fixed port, shell, `/tmp`, or host-specific absolute path
  is used;
- the dedicated workspace is rejected beneath inherited provider state or any
  Git worktree ancestor;
- fixture hashes are verified, and each high-entropy deterministic canary is
  checked after every scenario for integrity and absence from captures and
  newly created scenario trees;
- candidate commands and the mock daemon are owned by timeout-bounded RAII
  guards that kill and reap children on success, error, and timeout;
- the normalized suite is run under two distinct roots (one with spaces and
  one with Unicode) and must produce byte-identical results.

Host PSS and real-model observations are supplemental only. They can never be
required for the portable acceptance result.

## Build and run

From the repository root, verify the in-workspace suite and build the
process-backed candidate separately:

```bash
cargo build -p icm-mcp-eval --locked --offline
cargo run -p icm-mcp-eval --locked --offline -- verify-design \
  --suite-root crates/icm-mcp-eval
cargo build -p icm-cli --locked --offline --no-default-features \
  --features backend-sqlite,http-api
```

The full runner intentionally operates on a staged suite in a dedicated,
non-Git workspace. This keeps candidate paths and all generated evidence out
of the checkout and makes the same command usable in CI:

```bash
set -euo pipefail
root="$(mktemp -d /tmp/icm-mcp-eval.XXXXXX)"
mkdir -p "$root"/{suite,candidate,runs/self-test,evidence}
cp crates/icm-mcp-eval/Cargo.toml "$root/suite/"
cp -a crates/icm-mcp-eval/contracts \
      crates/icm-mcp-eval/fixtures \
      crates/icm-mcp-eval/goldens "$root/suite/"
install -m 0755 target/debug/icm "$root/candidate/icm"
target/debug/icm-mcp-eval self-test --expect candidate \
  --workspace-root "$root" \
  --suite-root "$root/suite" \
  --candidate "$root/candidate/icm" \
  --work-root "$root/runs/self-test" \
  --evidence-root "$root/evidence" \
  --run-label candidate
```

To inspect a non-acceptance observation instead, use `record-baseline` with
an explicit run label. It never updates committed goldens. `--expect
baseline` permits `UNSUPPORTED_BASELINE`; `--expect candidate` requires every
scenario to pass. The current frozen inventory includes provider scenarios,
which require the candidate's trusted-provider CLI capability.

All paths may be relative or absolute. The runner resolves them before
creation. Candidate, suite, work, and evidence must be disjoint strict
children of a dedicated, non-Git workspace. The workspace may be below
`HOME`, but it may not equal `HOME`/`USERPROFILE` or lie within inherited or
standard-default XDG, app-data, or macOS Library state directories.
Candidate environments, arguments, and working directories are checked not to
receive those real-state locations. Normalized output stores placeholders.

The package is named `icm-mcp-eval`, but frozen protocol identities may still
contain `icm-cleanroom-eval` or `icm-cleanroom-mock`. Those strings are
contract data covered by checksums/goldens; renaming them requires an explicit
contract revision, not a package rename.

Provider scenarios are frozen in the 294-scenario inventory. They require
the production candidate's trusted-provider CLI (`icm provider ...`); a
candidate without that capability is reported as unsupported in baseline
mode and fails candidate acceptance rather than being silently omitted.

The loopback gate proves that configured proxy endpoints and the mock
integration's recorded peer/local sockets are loopback. It does not claim OS
firewall enforcement or observation of arbitrary sockets. Likewise, the
canary gate proves unchanged bytes and non-disclosure in stdout, stderr, raw
exchanges, and the scenario tree; it does not claim detection of an arbitrary
silent read.

`record-baseline` is intentionally separate from `run`: it writes an observed
artifact but never silently updates the committed SHA-256 golden contract.
Updating a golden requires an explicit reviewed file change. `run` enforces
all candidate gates and exits unsuccessfully if a capability is missing or a
scenario fails.
