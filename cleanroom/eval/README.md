# ICM clean-room evaluator

This package is a standalone, evaluation-first harness for the MCP improvement
program. It does not modify product code and it does not inspect user state.
The committed preregistration is the contract; the runner invokes a real ICM
binary and records real wire responses, synthetic-tree mutations, configured
loopback HTTP integration traffic, and process topology.

The required lane is deliberately portable and hermetic:

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
cargo run --locked --offline -- self-test \
  --workspace-root /path/to/icm-workspace \
  --suite-root /path/to/icm-workspace/cleanroom/eval \
  --candidate /path/to/icm-workspace/target/debug/icm \
  --work-root /path/to/icm-workspace/.cleanroom-eval-runs/self-test \
  --evidence-root /path/to/icm-workspace/.cleanroom-eval-evidence

cargo run --locked --offline -- record-baseline \
  --workspace-root /path/to/icm-workspace \
  --suite-root /path/to/icm-workspace/cleanroom/eval \
  --candidate /path/to/icm-workspace/target/debug/icm \
  --work-root /path/to/icm-workspace/.cleanroom-eval-runs/baseline \
  --evidence-root /path/to/icm-workspace/.cleanroom-eval-evidence \
  --run-label untouched-develop

cargo run --locked --offline -- run \
  --workspace-root /path/to/icm-workspace \
  --suite-root /path/to/icm-workspace/cleanroom/eval \
  --candidate /path/to/replacement/icm \
  --work-root /path/to/icm-workspace/.cleanroom-eval-runs/candidate \
  --evidence-root /path/to/icm-workspace/.cleanroom-eval-evidence \
  --run-label replacement
```

All paths may be relative or absolute. The runner resolves them before
creation. Suite, work, and evidence must be pairwise-disjoint strict children
of the explicit workspace root. The workspace may be a dedicated project
below `HOME`, but it may not equal `HOME`/`USERPROFILE` or lie within inherited
or standard-default XDG, app-data, or macOS Library state directories.
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

The `archive` command copies the evaluator and configured evidence tree to a
new output root and writes `MANIFEST.sha256`. It refuses to overwrite an
existing archive, requires suite/evidence/report/output to be pairwise
disjoint before creating output, and excludes only evaluator build/run scratch
directories.
