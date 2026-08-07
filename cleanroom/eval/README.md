# ICM clean-room evaluator

This package is a standalone, evaluation-first harness for the MCP improvement
program. It does not modify product code and it does not inspect user state.
The committed design is the contract; the runner invokes a real ICM
binary and records real wire responses, synthetic-tree mutations, configured
loopback HTTP integration traffic, and process topology.

The initial design was frozen on 2026-08-05 before replacement implementation.
Later revisions, including v9, are post-implementation audit/spec corrections;
v9 was frozen before the final candidate run. Its provider/OpenCode and HTTP
session/Origin corrections did not change the 294 scenarios or thresholds.

The required lane provides portable controlled-input isolation:

- every scenario receives a new synthetic home, XDG tree, Windows profile
  tree, database, configuration tree, working directory, and environment;
- the child environment is cleared and rebuilt from an explicit allowlist;
- embeddings are disabled for product behavior and the proxy topology lane
  uses a deterministic loopback mock daemon/model;
- no provider account, credential, real configuration, Git configuration,
  external service, fixed port, shell, `/tmp`, or host-specific absolute path
  is used;
- fixture hashes are verified, and each high-entropy deterministic canary is
  checked for integrity and absence from captures and the entire scenario
  tree;
- candidate commands and the mock daemon are owned by timeout-bounded RAII
  guards that kill and reap children on success, error, and timeout;
- the normalized suite is run under two distinct roots (one with spaces and
  one with Unicode) and must produce byte-identical results.

Host PSS and real-model observations are supplemental only. They can never be
required for the portable acceptance result.

## Build and run

From this directory, after the repository dependencies have been fetched by a
normal workspace build:

```text
cargo build --locked --offline
cargo run --locked --offline -- verify-design --suite-root .
cargo run --locked --offline -- self-test --expect baseline \
  --workspace-root /path/to/dedicated-eval-workspace \
  --suite-root /path/to/dedicated-eval-workspace/suite \
  --candidate /path/to/dedicated-eval-workspace/candidate/icm \
  --work-root /path/to/dedicated-eval-workspace/runs/self-test \
  --evidence-root /path/to/dedicated-eval-workspace/evidence

cargo run --locked --offline -- record-baseline \
  --workspace-root /path/to/dedicated-eval-workspace \
  --suite-root /path/to/dedicated-eval-workspace/suite \
  --candidate /path/to/dedicated-eval-workspace/candidate/icm \
  --work-root /path/to/dedicated-eval-workspace/runs/baseline \
  --evidence-root /path/to/dedicated-eval-workspace/evidence \
  --run-label untouched-develop

cargo run --locked --offline -- run \
  --workspace-root /path/to/dedicated-eval-workspace \
  --suite-root /path/to/dedicated-eval-workspace/suite \
  --candidate /path/to/dedicated-eval-workspace/candidate/icm \
  --work-root /path/to/dedicated-eval-workspace/runs/candidate \
  --evidence-root /path/to/dedicated-eval-workspace/evidence \
  --run-label replacement
```

All paths may be relative or absolute. The runner resolves them before
creation. Candidate, suite, work, and evidence must be disjoint strict
children of a dedicated, non-Git workspace. The workspace may be below
`HOME`, but it may not equal `HOME`/`USERPROFILE` or lie within inherited or
standard-default XDG, app-data, or macOS Library state directories.
Candidate environments, arguments, and working directories are checked not to
receive those real-state locations. Normalized output stores placeholders.

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
