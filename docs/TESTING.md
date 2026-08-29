# Testing

uncia's hard problem is that half of it talks to AWS. This describes how that
half gets tested without a round trip to a real account for every change.

## Layers

| Layer | Needs | Proves |
|---|---|---|
| Unit | nothing | normalization logic, diff rules |
| **Replay** | nothing | the collectors against **real recorded AWS bytes**, end to end |
| LocalStack | container runtime | the full loop incl. Terraform, no AWS account |
| Live | AWS credentials | ground truth |

Everything except the last two runs in CI on every push (`cargo test
--all-targets`).

## Files

| Path | What |
|---|---|
| `tests/collector_replay.rs` | replay tests — collectors against recorded AWS bytes; `seed_`-prefixed tests assert against hand-written data, the rest against a real capture |
| `tests/recordings/` | the recordings themselves (see status below) |
| `examples/capture_recording.rs` | records + scrubs a new recording from a real account |
| `scripts/localstack.sh` | `up` / `down` / `status` for the LocalStack target |
| `infra/` | the two container-runtime definitions the script picks between |

There is deliberately no `make` wrapper for `cargo test` / `cargo clippy` —
cargo is the build tool, and a second spelling of the same commands only
invites the two to disagree. `scripts/localstack.sh` exists because container
orchestration is the one part cargo has no answer for.

## Replay harness

The collectors' unit tests build `SecurityGroup` / `Instance` values with SDK
builders, which skips XML deserialization entirely — if AWS's wire format
differed from what a collector assumes, no unit test would notice. The replay
tests (`tests/collector_replay.rs`) close that gap: recorded HTTP responses are
fed back through the *real* SDK, so the bytes travel the same deserialization
path a live call uses, then on through the collector and the diff.

`tests/collector_replay.rs` covers the scenarios the live smoke test used to:
a clean account reporting no drift, console edits showing up as drift
(including an IMDSv2 downgrade), and a vanished instance reading as `Missing`.

### Recording status

| Recording | Source | Grounds |
|---|---|---|
| `tests/recordings/aws-two-resources.json` | ✅ **captured** from a real account (us-east-1) | security groups, empty-account instances |
| `tests/recordings/aws-instance-seed.json` | ⚠️ **seed** — hand-written | a populated `DescribeInstances` |

The split exists because the captured account has **no EC2 instances**: its
`DescribeInstances` returns an empty `reservationSet`, which is real and worth
testing but cannot ground the instance collector. Rather than let invented
instance bytes sit in a file labelled "captured", the guess lives in its own
recording and the tests that use it carry a `seed_` prefix, so a reader can
tell at a glance which assertions are ground truth.

A seed exercises deserialization and locks in a regression baseline, but it
cannot prove AWS emits exactly those bytes — it was written from the documented
wire format, so replaying it partly tests our own assumptions against
themselves. (Same discipline as `tests/state_equivalence.rs`, whose fixtures
come from a real `terraform apply` rather than from what we believed Terraform
emits.)

**To ground the instance collector**, run the capture against an account that
has a running instance and split the `DescribeInstances` response into
`aws-instance-seed.json`, renaming it and flipping its row above.

#### What the captured recording already proved

Worth recording, because these were written blind against the API docs and had
never been checked against AWS:

- **Self-referencing rules.** A default VPC security group allows all traffic
  from itself, which AWS models as a `UserIdGroupPair` holding the group's own
  id. The collector's `self: true` normalization handles it correctly.
- **Absent ports.** All-traffic rules omit `fromPort`/`toPort` entirely on the
  wire; they normalize to `0` as Terraform represents them.
- **Empty tag values.** `<value/>` becomes `""`, not a missing key.
- **Unknown fields are harmless.** Real responses carry `securityGroupArn`,
  which the seed never had and the collector ignores without complaint.

### Capturing from a real account

Read-only; makes exactly the `Describe*` calls the collectors already make.

```sh
AWS_REGION=us-east-1 cargo run --example capture_recording -- \
    tests/recordings/aws-two-resources.json
```

Then update `tests/fixtures/replay_state_clean.json` so the declared side
matches the captured resources, and re-run `cargo test`.

It's an example rather than a subcommand, so it never reaches the shipped
binary.

**Scrubbing.** Recordings are committed, so identifiers are replaced before
anything is written: account IDs, resource IDs, IPs, principal IDs, request
IDs. Substitution is *consistent* — a security group referenced from an
instance scrubs to the same placeholder in both responses, so relationships
survive. Values with rule semantics (`0.0.0.0`) are deliberately left intact;
scrubbing those would quietly turn "open to the world" into "open to one host"
and change what the recording asserts. The scrubber is unit-tested
(`cargo test --all-targets`) because a bug in it leaks real account data into
a public repository.

Tag *values* are **not** scrubbed — the tests assert on them. Read the diff
before committing.

## LocalStack

Useful because uncia needs both halves: point Terraform at LocalStack, apply,
and you have a real state file and a live cloud to diff against, with no AWS
account at all. Mutate something with `awslocal` and drift appears.

```sh
scripts/localstack.sh up       # podman quadlet if available, else docker compose
scripts/localstack.sh status
scripts/localstack.sh down
```

Two runtimes ship because they win in different places:

- **Podman quadlet** (`infra/uncia-localstack.container`) for local work —
  rootless, no root-owned daemon, no `docker` group. `Notify=healthy` makes
  systemd report the unit started only once LocalStack is actually healthy, so
  tests can't race startup. Matches uncia's own argument that a drift detector
  shouldn't require privileged agents.
- **Docker Compose** (`infra/docker-compose.yml`) for CI, where
  `systemctl --user` has no dbus session.

Tests must only depend on something answering at `UNCIA_TEST_ENDPOINT`
(default `http://localhost:4566`), never on a specific runtime.

**Caveat:** LocalStack *approximates* AWS. It validates uncia's logic loop, not
the normalization assumptions — those are what the replay recordings cover.
And if the event-driven work lands, LocalStack's Lambda support wants a
container socket mounted, which is where rootless podman gets genuinely awkward;
expect to reach for Docker in that specific suite.
