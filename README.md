# uncia

**Drift detection for IaC that goes beyond value diffs** — catches infrastructure
that looks unchanged but no longer means what it used to.

[![CI](https://github.com/lazyIhsan/uncia/actions/workflows/ci.yml/badge.svg)](https://github.com/lazyIhsan/uncia/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust 2024 edition](https://img.shields.io/badge/rust-2024%20edition-orange.svg)](Cargo.toml)

## What it does

uncia compares two pictures of your infrastructure:

- **Declared intent** — what your IaC says should exist, read from
  `terraform show -json` / `tofu show -json`, or a raw `.tfstate` file.
- **Control-plane reality** — what the cloud provider's APIs report actually
  exists, read through read-only collectors.

It diffs the two and reports drift with a strict exit code, so CI/CD can gate
on it:

```
$ uncia check --state state.json
[Medium] aws_security_group.existing: 'tags' drifted
    declared: {}
    actual:   {"test-ec2-collector":""}

1 drift(s) detected
$ echo $?
2
```

Exit codes follow `terraform plan -detailed-exitcode` convention: `0` no
drift, `1` error, `2` drift found.

**No agent. No kernel access. No workload instrumentation.** uncia reads
Terraform/OpenTofu state and calls cloud APIs — that's the entire trust and
privilege footprint. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for
the full design rationale, including the invariants and the non-goals that
keep it that way.

### Behavioral drift vs. semantic drift

uncia distinguishes two kinds of drift:

- **Behavioral drift** — a field's value no longer matches what was declared
  (`instance_type` changed from `t3.medium` to `t3.large`). Straight value
  comparison.
- **Semantic drift** — the declared and live values are byte-for-byte
  identical, but the resource no longer *means* what it used to, because
  something it depends on changed. This is the differentiator — see
  [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#the-two-drift-classes) for
  why it's the harder and more interesting half of the problem, and
  [`docs/SEMANTIC-DRIFT.md`](docs/SEMANTIC-DRIFT.md) for the design.

Two semantic relations ship today. **Security-group membership:** a rule
reading `allow 443 from sg-app` is byte-identical before and after someone
attaches `sg-app` to an instance that isn't in your state file — every field on
every declared resource still matches, so a field diff is *correct* to stay
silent, and the set of machines that can reach your web tier grew anyway:

```
$ uncia check --state state.json
[High] aws_security_group.web: `ingress` unchanged but its meaning drifted (sg_membership)
    via:      sg-app
    declared: ["tcp/443-443/member:i-worker"]
    actual:   ["tcp/443-443/member:i-console","tcp/443-443/member:i-worker"]
```

**Instance exposure** is the mirror image: an instance's own declared security
groups can stay exactly as written while a rule gets added to one of them in
the console, quietly widening what can reach that instance. Same shape, via
the group the exposure came from, opposite direction — an instance's meaning
resolved from the groups it references, rather than a group's meaning resolved
from the instances that reference it.

Every semantic finding carries the `via` path that produced it, so the claim is
checkable against your account without reading uncia's source.

`sg_membership` and `instance_exposure` aren't the first two of many
equally-weighted relations — semantic drift in uncia is deliberately scoped to
**network exposure**: security groups and whatever else determines what can
reach what. See
[why network-exposure drift, not general drift](docs/ARCHITECTURE.md#why-network-exposure-drift-not-general-drift)
for the reasoning and the relations planned next inside that niche.

## Status

Pre-1.0, actively developed, no packaged releases yet.

| | |
|---|---|
| Declared-state inputs | `terraform show -json`, `tofu show -json`, raw `.tfstate` (auto-detected) |
| Live collectors | AWS only — EC2 instances, Security Groups (inline *and* separately-declared rules) |
| Drift detection | Behavioral (literal field diff) + semantic (security-group membership, instance exposure) |
| History / TUI | In progress (`src/store`, `src/tui`), not yet wired to the CLI |

Full scope, including what's deliberately *not* supported and why, is in the
[non-goals section](docs/ARCHITECTURE.md#non-goals) of the architecture doc —
worth reading before filing an issue asking for eBPF collection or
auto-remediation.

## Install

No published crate or binaries yet — build from source:

```sh
git clone https://github.com/lazyIhsan/uncia.git
cd uncia
cargo build --release
./target/release/uncia check --state state.json
```

Requires Rust 1.85+ (2024 edition). AWS calls use the standard credential
chain (environment variables, `~/.aws/credentials`, instance/task role — the
same resolution order as the AWS CLI).

## Usage

```sh
# From a plan/show export
terraform show -json > state.json
uncia check --state state.json

# Piped straight from Terraform
terraform show -json | uncia check --state -

# OpenTofu works the same way — identical schema
tofu show -json | uncia check --state -
```

## Architecture

```
terraform show -json ─┐
                       ├─► diff ─► DriftReport ─► store (history)
cloud API collectors ─┘                      └─► tui (inspect)
```

- `src/state/` — parses declared state (`terraform.rs`, `tfstate.rs`)
- `src/collector/` — fetches live state; `Collector` is the extension point
  for new clouds/services
- `src/diff/` — joins the two by cloud ID and produces the drift report
- `src/store/`, `src/tui/` — history persistence and inspection (in progress)

Full design doc, invariants, and open questions: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

### Open core

uncia is developed across two repositories. This repo is the core engine —
resource/drift types, the diff engine, collectors, CLI, and TUI — everything
that runs against your cloud account and needs your trust, and all of it is
auditable here. The differentiated semantic-correlation and compliance layer
lives in a private companion repo. See
[the public/private boundary](docs/ARCHITECTURE.md#the-public--private-boundary)
for the exact rule for what lives where.

## Development

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

Collector tests replay recorded real AWS wire responses rather than mocking
the SDK, so a change in AWS's actual response shape gets caught. For the full
testing philosophy — replay recordings, the LocalStack loop, and how to
capture a new recording — see [`docs/TESTING.md`](docs/TESTING.md).

```sh
scripts/localstack.sh up      # spin up LocalStack for a local Terraform + drift loop
scripts/localstack.sh status
scripts/localstack.sh down
```

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
