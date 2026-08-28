# Architecture

This document describes what uncia is, the boundaries it deliberately holds,
and the things it deliberately does *not* do. It is a scoping document as much
as a design one — the [Non-goals](#non-goals) section is load-bearing.

## What uncia is

uncia is a **control-plane drift detector**. It compares two pictures of your
infrastructure:

- **Declared intent** — what your IaC says should exist, read from
  `terraform show -json` (and the identical `tofu show -json`) in
  `src/state/terraform.rs`.
- **Control-plane reality** — what the cloud provider's APIs report actually
  exists, read through collectors (`src/collector/`).

It diffs the two (`src/diff/`), produces a drift report (`src/types/drift.rs`),
and persists history so drift can be tracked over time (`src/store/`).

**No agent. No kernel access. No workload instrumentation.** uncia reads
Terraform state and calls cloud APIs. That is the entire trust and privilege
footprint, and keeping it that small is a feature, not a limitation — it is
what lets uncia run anywhere, including against serverless and managed
platforms, without asking a security team to trust a root daemon.

The pipeline:

```
terraform show -json ─┐
                      ├─► diff ─► DriftReport ─► store (history)
cloud API collectors ─┘                     └─► tui (inspect)
```

## The two drift classes

uncia distinguishes two kinds of drift. The distinction is the point of the
project.

### Behavioral drift — literal field diff

A field's value no longer matches what was declared. The Terraform says
`instance_type = "t3.medium"`, the live instance is `t3.large`. This is a
straight value comparison. It is **table stakes** — every drift tool does it,
and uncia does it because it must, not because it is interesting.

### Semantic drift — the value is identical, the meaning changed

The declared value and the live value are byte-for-byte equal, yet the
resource no longer *means* what it used to, because something it depends on
changed. Examples:

- A security-group rule still reads `allow 443 from sg-abc`. `sg-abc` is
  unchanged in your Terraform — but its *membership* changed, so a different
  (larger) set of instances can now reach port 443. Same value, different
  blast radius.
- An IAM policy references a managed policy by ARN. The ARN is unchanged; the
  managed policy's *contents* drifted upstream. Effective permissions changed
  with no diff in your state.
- A route table entry points at a peering connection or NAT gateway that was
  replaced out from under it. The reference looks stable; reachability is not.

A literal field diff sees none of these — the fields are equal. Detecting them
requires reasoning about a resource's *effective* meaning in context, not just
its stored attributes. **Semantic drift is the differentiator.** Behavioral
drift earns the right to be in the room; semantic drift is why anyone stays.

The mechanism is specified in [`SEMANTIC-DRIFT.md`](SEMANTIC-DRIFT.md); the
first relation — security-group membership — ships today.

## The public / private boundary

uncia is developed as open core across two repositories.

- **`uncia`** (this repo, public) — the core engine: the drift and resource
  types, the diff engine, the collectors (the `Collector` trait and its
  implementations), the CLI, and the TUI. Everything needed to detect and
  inspect drift against your own cloud accounts lives here and is auditable.
- **`unciaroot`** (private) — the differentiated intelligence layer: the
  extended semantic relation catalog, cross-account and cross-run correlation,
  audit trails, and compliance packaging (mapping drift to controls, generating
  the evidence a regulated org needs to prove live systems match audited specs).

The guiding rule: anything that runs against a customer's infrastructure and
needs their trust belongs in the open repo; the correlation and compliance
intelligence that runs on our side is what `unciaroot` protects.

Semantic correlation straddles that line, so it is split rather than assigned:
the **engine** is open (a wrong engine fails silently, and only its source
reveals drift it never reported), while **additional relations** may be private,
because a relation's claim arrives with the `via` path that makes it checkable
without reading its source. See
[`SEMANTIC-DRIFT.md`](SEMANTIC-DRIFT.md#where-the-line-actually-falls) for the
test and the two constraints it puts on the private side.

## Non-goals

These are out of scope **on purpose**. Each carries the condition under which
it would be reconsidered. Absence from this list is not permission; presence
here is a deliberate boundary, not a forgotten feature.

- **eBPF / runtime (data-plane) collection is out of scope for v1.** uncia
  observes the control plane only. Watching syscalls, process execs, or live
  network flows would make uncia a runtime-security tool competing with
  Falco/Tetragon, and would import a kernel-agent trust and operational burden
  that contradicts the "no agent" footprint above.
  *Revisit once semantic detection ships and proves out against real AWS
  accounts, and only as an additional collector behind the existing seam — a
  runtime agent would be open-sourced into this repo for auditability, never
  shipped as a closed root daemon.*

- **No remediation. Detection only.** uncia reports drift; it does not modify
  cloud resources or rewrite Terraform. Collectors are strictly read-only.
  *Revisit only after detection is trusted in production; auto-remediation on
  top of an immature detector is how tools get uninstalled.*

- **No statistical inference or machine-learned baselines.** Drift in uncia is
  **deterministic and fully observed**: it is a function of declared state and
  observed live state, both of which are read in full. There is no probabilistic
  "this looks anomalous" verdict. A drift finding must always trace to a
  concrete, inspectable difference.
  *Revisit never for the core diff; any anomaly-scoring would live in
  `unciaroot` as an advisory layer, not in the deterministic engine.*

- **Multi-IaC beyond the Terraform state schema is out of scope for v1.** uncia
  reads the Terraform JSON state schema. **OpenTofu is in scope** — `tofu show
  -json` emits the same schema, so it works through the same code path at
  effectively no cost, and is supported as a first-class input. Pulumi,
  CloudFormation, and other formats with different schemas are deferred.
  *Revisit (Pulumi/CFN) once the resource model has stabilized against the
  Terraform schema; the `state` module is the seam where another schema would
  plug in.*

- **Rules owned by a *different state file* than their group are not
  reconciled.** A group's rules are read from its inline `ingress`/`egress`
  blocks **and** from any `aws_security_group_rule` /
  `aws_vpc_security_group_ingress_rule` / `_egress_rule` resources declared
  alongside it, so either style is checked correctly. But if the group lives in
  one state file and its rules in another, the group's file sees no sibling
  rules and reports the live rules as drift. That is defensible — the file
  declares the group and thereby claims its rule set — but it is a false
  positive for a split-state layout.
  *Revisit together with unmanaged detection: both need uncia to know that
  another state file legitimately owns something it can see.*

## Invariants

Small facts that are expensive to rediscover. Violating one is a bug even if
the code compiles.

- **`ResourceId` is the Terraform address, not the cloud ID.** `ResourceId`
  wraps the Terraform resource address (e.g.
  `aws_instance.web`). The cloud-assigned identifier (e.g. `i-0abc123`) lives
  separately in the resource's `attributes["id"]`. These are different keys
  with different lifecycles — the Terraform address is stable across replaces,
  the cloud ID is not — and **must not be conflated**. Diffing keys on the
  Terraform address; collectors resolve the cloud ID from attributes.

- **Collectors are read-only.** A collector fetches live state and never
  mutates cloud resources or Terraform state. This is what makes "detection
  only" an architectural guarantee rather than a convention.

- **Collectors return observations keyed by cloud ID, never by Terraform
  address.** A collector talking to a cloud API cannot know Terraform
  addresses; it returns `LiveResource`s keyed by cloud ID, and only the diff
  joins them to declared resources — via `Resource::cloud_id()`, never via
  `ResourceId`.

- **Encrypted or unreadable state is a hard failure, not a parse error.**
  OpenTofu (and some Terraform setups) can encrypt state at rest. uncia does
  not hold decryption keys and must not try to partially parse, guess at, or
  silently skip state it cannot read — doing so would produce a confidently
  wrong report in which every resource looks deleted. Encountering encrypted or
  otherwise unreadable state must fail loudly with a clear message, never
  degrade to an empty or partial parse.

## Open questions

Deliberately undecided. Recorded here so "unresolved" is distinguishable from
"forgotten."

- **How does uncia tell *intentional* drift from *meaningful* drift?** Someone
  changing prod on purpose (a hotfix, an ASG scaling event, a break-glass fix)
  and the effective security posture shifting are both "drift," but only one of
  them should raise alarm. This is the noise-vs-signal question that decides
  whether uncia becomes a trusted audit tool or gets muted in two weeks, and it
  is **distinct from severity**: severity asks *how bad*, intentionality asks
  *was this expected*. Where does the signal come from — change-source
  attribution (e.g. CloudTrail actor/principal), an approvals or change-window
  feed, an explicit allow-list of expected drift, or the IaC-intent model
  itself?

- ~~**How is semantic drift's dependency graph built?**~~ Answered by
  [`SEMANTIC-DRIFT.md`](SEMANTIC-DRIFT.md): **both** graphs are built — the
  divergence between the declared and live graphs *is* the signal — from
  attribute values rather than Terraform references, since the live side has no
  references to compare against. Its home is the open repo, with the extended
  relation catalog in `unciaroot` — settled, and reflected in the
  [public/private boundary](#the-public--private-boundary) above.

- **What is the collector interface's exact contract** once there is more than
  one AWS service and, eventually, more than one cloud? The `Collector` trait
  is a starting point, not a settled boundary.

- **How is drift severity assigned?** `Severity` exists on the type, but the
  policy that maps a given drift to a severity is unspecified. Static rules,
  configurable policy, or something derived from blast radius?

- **What is the history/store granularity?** Per-run snapshots, per-resource
  event log, or both? This affects what questions the TUI and future compliance
  reporting can answer.
