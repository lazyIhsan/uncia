# Design: semantic drift

**Status: phase 1 shipped, proven against real AWS bytes.** The engine, the
`sg_membership` relation, the three guards, and the end-to-end replay test are
all implemented and passing (see [Phasing](#phasing)). This document specifies
the mechanism, fixes the decisions that are cheap now and expensive later, and
names what it deliberately leaves unsettled.

Read [`ARCHITECTURE.md`](ARCHITECTURE.md) first — this document assumes the
[two drift classes](ARCHITECTURE.md#the-two-drift-classes) and the
[invariants](ARCHITECTURE.md#invariants), and extends both.

## Why this document exists

Semantic drift is the stated differentiator: *"behavioral drift earns the right
to be in the room; semantic drift is why anyone stays."* But the architecture
doc only gives examples of it. Examples are not a specification — they do not
say what to compare against, where the dependency graph comes from, or how a
finding stays falsifiable. This closes that gap for one relation, end to end,
and leaves a shape the rest can follow.

## The problem, stated precisely

Behavioral drift is a function of one resource:

```
behavioral(r) = declared[r].attributes ≠ live[r].attributes
```

That is the entire current engine (`src/diff/behavioral.rs`). It compares a
resource's stored attributes against the same resource's live attributes, field
by field. Every field it compares belongs to the resource being compared.

Semantic drift is a function of a resource **and its neighbourhood**:

```
semantic(r) = effective(declared, r) ≠ effective(live, r)
              given declared[r].attributes == live[r].attributes
```

Where `effective` resolves a resource's stored attributes into what they
actually *mean* by pulling in the state of the resources they reference. The
guard clause is the definition, not an optimization: if the attributes
themselves differ, that is behavioral drift and is already reported.

The consequence: **no amount of field-level comparison finds semantic drift.**
Not more fields, not deeper fields, not better normalization. The information
needed is not in the resource. This is why it is a separate engine and not a
flag on the existing one.

## The worked example (and the current blind spot)

Terraform declares two security groups and one instance:

```hcl
resource "aws_security_group" "web" {
  ingress { from_port = 443, to_port = 443, protocol = "tcp",
            security_groups = [aws_security_group.app.id] }
}
resource "aws_security_group" "app" { }
resource "aws_instance" "worker" { vpc_security_group_ids = [aws_security_group.app.id] }
```

Someone launches an instance in the console — not in Terraform — and attaches
`sg-app` to it.

What uncia reports today: **nothing.** And every individual check is correct:

| Check | Result | Why |
|---|---|---|
| `aws_security_group.web` fields | clean | its rules are byte-identical; it still says `allow 443 from sg-app` |
| `aws_security_group.app` fields | clean | its own rules never changed |
| `aws_instance.worker` fields | clean | its `vpc_security_group_ids` never changed |
| the console instance | not checked | it is in no state file, and unmanaged detection is deferred (`behavioral.rs`) |

Meanwhile the set of machines that can reach port 443 on the web tier grew by
one. That is the whole product thesis in a single scenario: **a real,
security-relevant change that a complete and correct field diff cannot see.**

### Why this is not just "unmanaged resource detection"

The deferred TODO in `behavioral.rs` — reporting live resources declared
nowhere — would also notice that instance exists. It is worth being explicit
about why that is not the same feature, because it is the strongest objection
to this whole design.

Unmanaged detection says: *"there is an EC2 instance not in your state."* In a
real account that fires hundreds of times, most of them legitimately owned by
another state file, and it gets muted in a week.

Semantic drift says: *"an instance outside this state can now reach port 443 on
your web tier, via `sg-app`, which `aws_security_group.web` trusts."* One
finding, with the path that explains it.

Same underlying observation. The difference is entirely in the correlation —
which is precisely the thing being built here, and the reason signal-to-noise
is the design constraint rather than coverage.

## The central decision: what is the baseline?

Behavioral drift has an easy answer — Terraform tells you what should be.
Semantic drift does not: **Terraform never declares effective meaning.**
`security_groups = [sg-app]` says nothing about who is in `sg-app`. So there is
no declared baseline to read off the state file, and a baseline must be
constructed. Three candidates:

**(a) Resolve both sides from the state they belong to.** Compute the effective
meaning of declared state using declared state, and the effective meaning of
live state using live state, then compare the two. In the example: declared
members of `sg-app` = instances *in the state file* referencing it; live members
= instances *in the account* referencing it. Fully deterministic, a function of
two fully-read inputs, and it needs no history. It fails only when a dependency
is not Terraform-managed at all — an AWS-managed IAM policy has no declared
contents to resolve.

**(b) Compare against the previous run.** Take effective meaning now versus
effective meaning at the last run, from `src/store`. This handles the
managed-policy case, which (a) cannot. But it is change detection, not drift
detection: it is not a function of declared state, so it answers "did this
move?" rather than "does this match intent?" It also requires a store (today a
stub) and has no answer on first run.

**(c) Compare against an absolute policy.** "Port 443 must not be reachable
from outside the VPC." This is a policy engine — Checkov, tfsec — and a
different product. Being wrong relative to a rule is not drift.

**Decision: (a) is the engine. (b) is a later, clearly-labelled complement.
(c) is out of scope permanently.**

(a) is chosen because it preserves the deterministic-and-fully-observed
invariant exactly as written: drift stays a function of declared state and
observed live state, both read in full, with no probabilistic component and no
dependence on what uncia happened to see yesterday. (b) violates that framing
even when it is useful, so if it ships it must be reported as a distinguishable
finding class and never silently mixed into (a)'s results — a user must always
be able to tell "this disagrees with your IaC" from "this changed since
Tuesday."

## Mechanism

### Two graphs, not one

[`ARCHITECTURE.md`](ARCHITECTURE.md#open-questions) asks whether the dependency
graph comes from Terraform references or live cloud relationships. The answer
is **both, because the divergence between them is the signal.** One graph has
nothing to compare against; semantic drift *is* the shape difference between
the declared graph and the live graph, at nodes whose own attributes agree.

Both graphs are built by the same function over different inputs:

```rust
fn build(resources: &[(ResourceKind, &str /* cloud id */, &Map<String, Value>)]) -> Graph
```

### Edges come from attribute values, not Terraform references

Terraform's `show -json` carries expression references in `configuration`, and
raw `.tfstate` carries a `dependencies` list. **Neither is used.** Edges are
derived from *attribute values*: `sg-app` appearing in an instance's
`vpc_security_group_ids` is an edge, whether Terraform wrote it as
`aws_security_group.app.id` or someone pasted the literal string.

Three reasons, in order of weight:

1. **The live side has no references at all.** AWS returns values, never
   Terraform expressions. If the declared graph were built from references and
   the live graph from values, they would not be comparable — and comparing
   them is the entire mechanism.
2. It works identically for `show -json` and raw `.tfstate`, which carry
   dependency metadata in different shapes.
3. A hardcoded id and a reference mean the same thing to AWS, so they should
   mean the same thing here.

This also keeps the existing identifier invariant intact: graph nodes are keyed
by **cloud ID**, because that is the only key both sides share. Terraform
addresses appear solely when a finding is reported.

### Relations

A relation names one way meaning flows between kinds, and is the unit of
extension — the semantic-drift equivalent of a collector:

```rust
trait Relation {
    fn name(&self) -> &str;
    /// Kinds that must be collectable for this relation to be resolvable.
    fn requires(&self) -> &[ResourceKind];
    /// The subject kind and field whose meaning this relation expands.
    fn subject(&self) -> (ResourceKind, &str);
    /// Expand the subject's stored value into its effective meaning.
    fn expand(&self, subject: &Node, graph: &Graph) -> Result<Value, String>;
}
```

`expand` is side-effect-free: it reads an already-built graph and returns a
value. It performs no I/O, so relations are unit-testable against hand-built
graphs with no AWS involved.

It returns `Result` rather than a bare `Value` because a subject can be
genuinely unresolvable, which implementation surfaced: a rule may reference a
group that is absent from the graph, meaning the group was deleted out from
under it. Expanding anyway would report the now-empty membership as a confident
narrowing finding, pinning the blame on the wrong resource — the real story is
that the group is gone, which the behavioral pass reports on the group itself.
`Err` carries the reason and routes to `Unresolved` instead.

### The pilot relation: `sg_membership`

Subject `(AwsSecurityGroup, "ingress")`, requires `[AwsInstance]`.

For each rule atom sourced from a security group, replace the group id with the
set of cloud IDs of instances whose `vpc_security_group_ids` contains it:

```
declared:  tcp/443-443 ← sg:sg-app    →  tcp/443-443 ← members{i-worker}
live:      tcp/443-443 ← sg:sg-app    →  tcp/443-443 ← members{i-worker, i-console}
```

Unequal, subject attributes equal → semantic drift on
`aws_security_group.web`, relation `sg_membership`, via `sg-app`.

This relation is the right pilot for three reasons: it is the exact scenario
`ARCHITECTURE.md` uses to motivate the feature, it needs **no new collectors**
(`DescribeInstances` is already unfiltered and `vpc_security_group_ids` is
already normalized on both sides), and it reuses `explode_rules` from
`behavioral.rs`, so the atom canonicalization stays in one place.

## Types

```rust
// src/types/drift.rs — DriftKind is #[non_exhaustive], so this is additive.
SemanticChanged {
    /// The subject field whose meaning changed (its value is unchanged).
    field: String,
    /// The relation that resolved it, e.g. "sg_membership".
    relation: String,
    declared_effective: Value,
    actual_effective: Value,
    /// Cloud IDs on the path from subject to cause. Never empty.
    via: Vec<String>,
}
```

`via` is **required, not diagnostic.** The invariant that a finding must trace
to a concrete, inspectable difference is doing real work here: a behavioral
finding is self-evident from `declared` versus `actual`, but a semantic finding
asserts something about a resource whose fields are provably unchanged. Without
the path it is an unfalsifiable claim, and users mute unfalsifiable claims. A
`SemanticChanged` with an empty `via` is a bug.

Alongside it, the "couldn't check" channel gains a sibling to `Unjoinable`:

```rust
pub struct Unresolved {
    /// `None` when the whole relation is unresolvable, not one subject.
    pub resource: Option<ResourceId>,
    pub relation: String,
    pub reason: String,
}
```

Same principle as `Unjoinable`, applied one level up: when a relation cannot be
resolved, that is neither drift nor health, and folding it into either would
make "no semantic drift" mean two different things.

`resource` is optional because the two unresolvable cases are genuinely
different in scope. A failed authority check is a property of the *state file* —
a file declaring no instances is not authoritative about group membership, full
stop — so it reports once with `None`; reporting per-resource would print one
line per declared group where one line is the truth. A subject-specific failure
(the deleted-group case above) still carries `Some(id)`.

## Guards against false positives

Semantic drift is inherently more inferential than a field diff, so the
failure mode to design against is a confident wrong finding. Three guards:

**1. Disjointness with behavioral drift.** A semantic finding is emitted only
when the subject's own field is unchanged. If `web`'s `ingress` drifted
literally, behavioral reports it and semantic stays silent on that
resource+field. The two classes never both fire on the same pair — which is
just the definition enforced in code.

This does *not* suppress a finding whose **cause** drifted behaviorally
elsewhere. If `sg-app`'s membership changed because a *declared* instance was
edited, that instance gets a behavioral finding and `web` still gets its
semantic one — the consequence is the point. They are linked by `via`, not
deduplicated.

**2. Authority check — the important one.** If declared state contains **no
resources of a kind a relation requires**, the state file is not the authority
on that relation and evaluating it would compare a real live set against a
vacuous empty one, firing on every rule.

Concretely: a state file that declares security groups but no instances would,
without this guard, report semantic drift on every SG-sourced rule in the
account. That is not a hypothetical — splitting network and compute into
separate state files is a common layout. So: `requires()` unsatisfied in
declared state → one `Unresolved`, not a pile of drift.

**3. Widening versus narrowing.** An effective set that *grew* (more principals
can reach something) and one that *shrank* are both divergence, and both are
reported — but they are not equally alarming. This is the first concrete input
uncia has to the open severity question: blast-radius direction is derivable
from the finding itself, with no new policy. Proposal: widening ≥ `High`,
narrowing `Low`. Recorded here as a proposal, not a settlement — severity
policy remains open.

## Interaction with the public/private boundary

`ARCHITECTURE.md` places "semantic correlation (resolving effective meaning
across related resources)" in the private `unciaroot`. Taken literally, that
would put this entire document in the other repo, so the split was decided
before code lands rather than after.

**Decided:** the base engine is open; the extended relation catalog is private.

- **`uncia` (open):** graph construction, the `Relation` trait, expansion,
  comparison, the three guards, `SemanticChanged` and `Unresolved` — plus the
  built-in relations needed for the tool to be genuinely useful standalone.
- **`unciaroot` (private):** additional relations registered through the same
  trait, cross-account and cross-run correlation, and compliance mapping.

The `Relation` trait is what makes the split cheap: it is the seam an extended
catalog plugs into, exactly as `Collector` is for cloud coverage.

### Where the line actually falls

"Base engine open, intricate parts private" is the right instinct but not yet a
usable rule — *intricate* is a judgement call, so it gets relitigated at every
PR that adds a relation. The operational test:

> **A finding must be verifiable from its `via` path alone, without reading the
> code that produced it.**

This is why the engine can never be private and why a private relation catalog
is nonetheless legitimate:

- **A wrong engine fails silently.** If graph construction or the guards are
  wrong, uncia misses real drift or fabricates it, and *no amount of inspecting
  the output reveals that* — the finding that never appeared leaves no trace.
  Only the source shows it. So the engine must be auditable.
- **A wrong relation fails loudly.** A relation's claim arrives with the path
  that justifies it. "`i-console` is in `sg-app`, which `web` trusts on 443" is
  checkable against the account in a minute by someone who has never seen the
  relation's source. The mandatory `via` field is what makes this true, which
  makes it structural rather than cosmetic: **`via` is the mechanism that
  licenses a closed relation catalog at all.**

Two constraints follow, and they bind the private side:

1. **A relation that cannot state its `via` path in terms the user can check
   independently must be open**, no matter how valuable. Failing that bar means
   the finding is unfalsifiable, which the falsifiability requirement already
   forbids — the boundary does not get to create an exception to it.
2. **The open relation set must stand on its own**, not function as a teaser.
   An open engine wired to one relation that nags toward an upgrade would spend
   exactly the trust the open repo exists to earn. `sg_membership` and
   `instance_exposure` are both in the open set for this reason.

## Testing

The replay harness (`tests/collector_replay.rs`) is the natural home — this is
the case it was built for. Layered:

1. **Relation unit tests.** `expand` is pure over a hand-built graph: no AWS, no
   recordings, no async. Most correctness lives here.
2. **Graph construction** over declared and live inputs, asserting both build
   identically from attribute values.
3. **Guard tests**, one per guard above — the authority check especially, since
   its failure mode is mass false positives.
4. **End-to-end replay** of the worked example. ✅ **Shipped** as
   `captured_undeclared_instance_joining_a_trusted_group_is_semantic_drift` in
   `tests/collector_replay.rs`.

Layer 4 needed a capture the original recording couldn't provide: **two
security groups (one referencing the other) and at least two instances in the
referenced group, only one of which is in the state file.** That's
`tests/recordings/aws-sg-membership.json` — captured, not hand-written, per
`docs/TESTING.md`'s seed-versus-captured discipline. A hand-written recording
of the flagship scenario would have proven only that the engine agrees with
the guess written to satisfy it; this proves it against real AWS bytes.

## Phasing

1. ~~Graph + `Relation` + `sg_membership` + `SemanticChanged` + `Unresolved`,
   with layers 1–3 of the testing plan.~~ **Shipped.** Behind no flag: it is
   additive, and the guards are the thing keeping it quiet.
2. ~~Capture the recording, land the end-to-end test.~~ **Shipped.** The
   feature is now proven against real AWS bytes, not just a hand-built graph.
3. Second relation — `instance_exposure` (an instance's effective exposure is
   the union of its attached groups' rules), which reuses the machinery and
   validates that the trait is actually a seam and not a one-off.
4. Reassess (b) — the temporal baseline — only once the store is real. It is
   the only path to undeclared dependencies like managed IAM policies, and it
   needs its own design pass, not a paragraph here.

`diff::behavioral::compare` stays public; a new `diff::compare` runs both
passes and owns disjointness, mirroring how `state::parse` dispatches while
`state::terraform::parse` stays public for direct testing.

## Out of scope

- **Reachability analysis.** Whether traffic *actually* flows involves route
  tables, NACLs, and peering. Semantic drift reports that a trust relationship
  changed meaning, not that a packet arrives.
- **Cross-account and cross-region graphs.** Single account, single region.
  *Revisit once a relation genuinely needs it; the graph is keyed by cloud ID,
  which is not globally unique across accounts, so this is a real change.*
- **Undeclared dependencies** (managed IAM policies, provider-owned resources).
  Requires baseline (b). Phase 4.
- **Transitive closure beyond one hop.** `sg_membership` resolves one level.
  Multi-hop expansion is a cost and explainability question — a five-hop `via`
  chain is not an explanation — and is deferred until a relation needs it.

## Open questions this does not settle

- **Intentional versus meaningful drift** is *sharpened* here, not answered.
  Semantic findings are higher-signal by construction, but an instance in
  another team's state file attaching to a shared group is expected and will
  fire. An allow-list is the obvious escape hatch and the wrong first move: it
  hides the finding instead of explaining it. The change-source attribution
  question in `ARCHITECTURE.md` matters more for this class than for
  behavioral drift, because the finding is about someone else's resource.
- **How many relations before the trait is right?** It is specified against
  one, which is not enough to know it. Phase 3 is the test, and the trait
  should be expected to change.
- **Graph cost at account scale.** Both graphs are built in memory from data
  already fetched, so the first cut is bounded by what collectors return
  today. Whether that holds at tens of thousands of resources is unmeasured —
  and should be measured before it is optimized.
