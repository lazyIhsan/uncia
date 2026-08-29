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
| `tests/collector_replay.rs` | replay tests — collectors against recorded AWS bytes, all of it captured from real accounts |
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
(including an IMDSv2 downgrade), a vanished instance reading as `Missing`, and
— since the second recording landed — the `sg_membership` semantic-drift
worked example end to end.

### Recording status

| Recording | Source | Grounds |
|---|---|---|
| `tests/recordings/aws-two-resources.json` | ✅ **captured** from a real account (us-east-1) | security groups (self-referencing rule), empty-account instances |
| `tests/recordings/aws-sg-membership.json` | ✅ **captured** from a real account (us-east-1) | a security group trusting a *different* group, a populated `DescribeInstances`, and the `sg_membership` semantic-drift worked example |

Both recordings are ground truth — there is no hand-written seed data left in
the replay suite. (There was, briefly: a `DescribeInstances` guess written
from the documented wire format, because the first captured account had no
running instances. It's gone now that `aws-sg-membership.json` grounds the
instance collector for real. Same discipline as `tests/state_equivalence.rs`,
whose fixtures come from a real `terraform apply` rather than from what we
believed Terraform emits.)

#### What the captured recordings already proved

Worth recording, because these were written blind against the API docs and had
never been checked against AWS:

- **Self-referencing rules.** A default VPC security group allows all traffic
  from itself, which AWS models as a `UserIdGroupPair` holding the group's own
  id. The collector's `self: true` normalization handles it correctly.
- **Cross-group rules.** A security group trusting a *different* group is the
  same `UserIdGroupPair` shape, just with someone else's id — and it's the
  shape the `sg_membership` semantic-drift relation actually depends on.
- **Absent ports.** All-traffic rules omit `fromPort`/`toPort` entirely on the
  wire; they normalize to `0` as Terraform represents them.
- **Empty tag values.** `<value/>` becomes `""`, not a missing key.
- **Unknown fields are harmless.** Real responses carry `securityGroupArn`,
  which the seed never had and the collector ignores without complaint.
- **The `sg_membership` worked example is real.** Two real running instances
  in one trusted group, only one declared in state, produces exactly the
  `SemanticChanged` finding the engine was designed to produce — not just what
  a hand-built graph agrees with. See `docs/SEMANTIC-DRIFT.md`.

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
