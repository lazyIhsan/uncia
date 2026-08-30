//! Capture real AWS responses into a replayable recording.
//!
//! This is the "record once" half of the replay harness: run it against a real
//! account, commit the (scrubbed) output, and the collector tests then replay
//! it offline forever — no credentials, no network, no back-and-forth.
//!
//! ```text
//! AWS_REGION=us-east-1 cargo run --example capture_recording -- \
//!     tests/recordings/aws-two-resources.json
//! ```
//!
//! It is an *example*, not a subcommand, so it lives entirely in dev builds
//! and never reaches the shipped `uncia` binary. It makes only the same
//! read-only `Describe*` calls the collectors already make.
//!
//! **Scrubbing.** Recordings get committed, so identifiers are replaced before
//! anything touches disk: account IDs, resource IDs, IP addresses, principal
//! IDs, and request IDs become stable placeholders. Substitution is
//! *consistent* — a security group referenced by an instance scrubs to the
//! same placeholder in both responses, so relationships survive and the diff
//! still works. Tag values are deliberately left alone (they carry meaning the
//! tests assert on), so **read the diff before committing** in case a tag
//! holds something sensitive.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use aws_sdk_ec2::config::BehaviorVersion;
use aws_smithy_runtime_api::client::interceptors::Intercept;
use aws_smithy_runtime_api::client::interceptors::context::AfterDeserializationInterceptorContextRef;
use aws_smithy_runtime_api::client::runtime_components::RuntimeComponents;
use aws_smithy_types::config_bag::ConfigBag;
use regex::Regex;
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: cargo run --example capture_recording -- <output.json>");
        std::process::exit(2);
    });

    let base = aws_config::load_defaults(BehaviorVersion::latest()).await;
    let region = base
        .region()
        .map(|r| r.to_string())
        .unwrap_or_else(|| "unknown".into());

    let mut scrubber = Scrubber::new();
    let mut responses = Vec::new();

    // One recorder per operation so responses are labelled without guessing.
    for (operation, collect) in [
        ("DescribeSecurityGroups", Op::SecurityGroups),
        ("DescribeInstances", Op::Instances),
    ] {
        let recorder = ResponseRecorder::default();
        let config = aws_sdk_ec2::config::Builder::from(&base)
            .interceptor(recorder.clone())
            .build();
        let client = aws_sdk_ec2::Client::from_conf(config);

        let count = match collect {
            Op::SecurityGroups => uncia::collector::aws::security_group::fetch(&client)
                .await?
                .len(),
            Op::Instances => uncia::collector::aws::ec2::fetch(&client).await?.len(),
        };
        let captured = recorder.take();
        eprintln!(
            "{operation}: {count} resource(s), {} response(s) captured",
            captured.len()
        );

        // A call that succeeded but recorded nothing means the capture hook is
        // broken, not that the account is empty — an API call always produces
        // a response. Fail loudly rather than writing a recording that would
        // replay as "no live resources" and quietly turn every declared
        // resource into false Missing drift. (Same rule the state parsers
        // hold: never let a silent empty stand in for a real read.)
        if captured.is_empty() {
            return Err(format!(
                "{operation} returned {count} resource(s) but no response was captured — \
                 the recording hook is not seeing response bodies; refusing to write an \
                 empty recording"
            )
            .into());
        }

        for (status, body) in captured {
            responses.push(json!({
                "operation": operation,
                "status": status,
                "body": scrubber.scrub(&body),
            }));
        }
    }

    // ELBv2 is a separate generated SDK crate with its own client and config
    // types, so it gets its own loop rather than a third entry above — an API
    // call always produces a response, so an account with zero load balancers
    // still captures one (empty) response, same "real empty vs. failed
    // capture" distinction as the EC2 calls.
    {
        let operation = "DescribeLoadBalancers";
        let recorder = ResponseRecorder::default();
        let config = aws_sdk_elasticloadbalancingv2::config::Builder::from(&base)
            .interceptor(recorder.clone())
            .build();
        let client = aws_sdk_elasticloadbalancingv2::Client::from_conf(config);

        let count = uncia::collector::aws::load_balancer::fetch(&client)
            .await?
            .len();
        let captured = recorder.take();
        eprintln!(
            "{operation}: {count} resource(s), {} response(s) captured",
            captured.len()
        );

        if captured.is_empty() {
            return Err(format!(
                "{operation} returned {count} resource(s) but no response was captured — \
                 the recording hook is not seeing response bodies; refusing to write an \
                 empty recording"
            )
            .into());
        }

        for (status, body) in captured {
            responses.push(json!({
                "operation": operation,
                "status": status,
                "body": scrubber.scrub(&body),
            }));
        }
    }

    let recording = json!({
        "scenario": "captured",
        "note": format!(
            "Captured from a real AWS account in {region} and scrubbed. \
             Every identifier is an obviously-synthetic placeholder — account \
             ids are 000000000000, resource ids are <prefix>-000...N, request \
             ids are 00000000-0000-0000-0000-0000000000NN, addresses are in \
             203.0.113.0/24 (TEST-NET-3) — so a reviewer can confirm at a \
             glance that nothing real survived. Substitution is consistent \
             across responses, so cross-references still resolve. Tag keys and \
             values are NOT scrubbed: the diff asserts on them."
        ),
        "region": region,
        "responses": responses,
    });

    std::fs::write(&out_path, serde_json::to_string_pretty(&recording)? + "\n")?;
    eprintln!("\nwrote {out_path}");
    eprintln!("review the diff before committing — tag values are not scrubbed.");
    Ok(())
}

enum Op {
    SecurityGroups,
    Instances,
}

/// Snapshots each response body as it arrives, without touching the request.
///
/// Deliberately an *interceptor* rather than a replacement HTTP client: the
/// SDK's own stack keeps building, signing and sending the request exactly as
/// it does for `uncia check`. Swapping in a recording HTTP client instead put a
/// wrapper in the request path and EC2 — whose query protocol POSTs a signed
/// form-encoded body — answered `400` with an empty body, which then surfaced
/// confusingly as "error parsing XML: no root element". Observing rather than
/// intermediating avoids that whole class of problem.
#[derive(Debug, Clone, Default)]
struct ResponseRecorder {
    captured: Arc<Mutex<Vec<(u16, String)>>>,
}

impl ResponseRecorder {
    /// Drain what has been captured so far.
    fn take(&self) -> Vec<(u16, String)> {
        std::mem::take(&mut *self.captured.lock().unwrap())
    }
}

impl Intercept for ResponseRecorder {
    fn name(&self) -> &'static str {
        "uncia::capture_recording::ResponseRecorder"
    }

    /// Deliberately the *after*-deserialization hook, not the before one.
    ///
    /// The orchestrator only buffers the response body during the
    /// deserialization phase (`read_body` swaps the stream for an in-memory
    /// `SdkBody` and leaves it on the response). At
    /// `read_before_deserialization` the body is still a stream, so
    /// `bytes()` returns `None` and a recorder there silently captures
    /// nothing — the calls succeed, and the recording comes out empty.
    fn read_after_deserialization(
        &self,
        context: &AfterDeserializationInterceptorContextRef<'_>,
        _runtime_components: &RuntimeComponents,
        _cfg: &mut ConfigBag,
    ) -> Result<(), aws_smithy_runtime_api::box_error::BoxError> {
        let response = context.response();
        // EC2 replies are XML text; anything not valid UTF-8 is skipped rather
        // than mangled, since it could not be scrubbed or reviewed anyway.
        if let Some(bytes) = response.body().bytes()
            && let Ok(body) = std::str::from_utf8(bytes)
            && !body.is_empty()
        {
            self.captured
                .lock()
                .unwrap()
                .push((response.status().as_u16(), body.to_string()));
        }
        Ok(())
    }
}

/// Replaces identifiers with stable placeholders, consistently across every
/// response in a capture.
struct Scrubber {
    rules: Vec<(Regex, &'static str)>,
    seen: HashMap<String, String>,
    next: usize,
}

impl Scrubber {
    fn new() -> Self {
        let patterns: Vec<(&str, &'static str)> = vec![
            // Resource identifiers, per prefix.
            (r"\bsg-[0-9a-f]{8,17}\b", "sg"),
            (r"\bi-[0-9a-f]{8,17}\b", "i"),
            (r"\bvpc-[0-9a-f]{8,17}\b", "vpc"),
            (r"\bsubnet-[0-9a-f]{8,17}\b", "subnet"),
            (r"\beni-[0-9a-f]{8,17}\b", "eni"),
            (r"\bami-[0-9a-f]{8,17}\b", "ami"),
            (r"\bvol-[0-9a-f]{8,17}\b", "vol"),
            (r"\bsnap-[0-9a-f]{8,17}\b", "snap"),
            (r"\br-[0-9a-f]{8,17}\b", "r"),
            (r"\bpl-[0-9a-f]{6,17}\b", "pl"),
            // ELBv2 resources are ARNs, not short prefixed ids — the account
            // digits get scrubbed by the account-id pattern below, but the
            // trailing hex id AWS assigns (e.g.
            // `loadbalancer/app/my-alb/50dc6c495c0c9188`) does not, so it gets
            // its own pattern. The load balancer's own *name* is left alone,
            // same as security group names — it's real declared config, not
            // a random identifier.
            (r"\b[0-9a-f]{16}\b", "elbid"),
            // IAM principal ids.
            (r"\b(?:AIPA|AROA|AIDA|ASIA|AKIA)[A-Z0-9]{8,}\b", "principal"),
            // Account ids.
            (r"\b\d{12}\b", "account"),
            // Request ids and other UUIDs.
            (
                r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
                "uuid",
            ),
            // Public/private addressing. Note the Rust regex crate has no
            // lookaround, so the "don't touch 0.0.0.0" carve-out is applied in
            // `scrub` rather than in the pattern.
            (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "ip"),
            // Hostnames that embed addressing.
            (
                r"\bec2-[\d-]+\.[a-z0-9.-]*compute[a-z0-9.-]*\.amazonaws\.com\b",
                "host",
            ),
            (r"\bip-[\d-]+\.[a-z0-9.-]*compute\.internal\b", "host"),
        ];

        Self {
            rules: patterns
                .into_iter()
                .map(|(p, kind)| (Regex::new(p).expect("valid scrub pattern"), kind))
                .collect(),
            seen: HashMap::new(),
            next: 0,
        }
    }

    fn scrub(&mut self, body: &str) -> String {
        let mut out = body.to_string();
        for (pattern, kind) in &self.rules {
            let mut replacements: Vec<(String, String)> = Vec::new();
            for m in pattern.find_iter(&out) {
                let original = m.as_str().to_string();
                if KEEP_VERBATIM.contains(&original.as_str()) {
                    continue;
                }
                if !self.seen.contains_key(&original) {
                    self.next += 1;
                    let placeholder = placeholder_for(kind, self.next);
                    self.seen.insert(original.clone(), placeholder);
                }
                let replacement = self.seen[&original].clone();
                replacements.push((original, replacement));
            }
            for (from, to) in replacements {
                out = out.replace(&from, &to);
            }
        }
        out
    }
}

/// Values that look like identifiers but carry rule semantics — scrubbing
/// these would change what the recording *means* (an SG open to the world
/// would silently become one open to a single host).
const KEEP_VERBATIM: &[&str] = &["0.0.0.0", "255.255.255.255", "127.0.0.1"];

fn placeholder_for(kind: &str, n: usize) -> String {
    match kind {
        // Deliberately all-zeros rather than AWS's conventional `123456789012`
        // example id. A reviewer has to be able to tell, at a glance, that a
        // committed recording carries no real account number — and a plausible
        // looking 12-digit id is indistinguishable from an unscrubbed one.
        // Every placeholder here is chosen to be obviously synthetic for the
        // same reason.
        "account" => "000000000000".to_string(),
        "uuid" => format!("00000000-0000-0000-0000-{n:012}"),
        "principal" => format!("AIPA{n:017}"),
        "ip" => format!("203.0.113.{}", n % 254 + 1),
        "host" => format!("host-{n}.example.invalid"),
        prefix => format!("{prefix}-{n:017}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns_all_compile() {
        // The regex crate has no lookaround; a bad pattern would only surface
        // at capture time, i.e. while pointed at a real account.
        Scrubber::new();
    }

    #[test]
    fn substitution_is_consistent_across_responses() {
        // The load-bearing property: an SG id appears in both the security
        // group response and the instance's groupSet. If those scrubbed
        // differently the recording would no longer describe the same
        // infrastructure and the diff tests would be meaningless.
        let mut scrubber = Scrubber::new();
        let sg_body = scrubber.scrub("<groupId>sg-0a1b2c3d4e5f60718</groupId>");
        let instance_body =
            scrubber.scrub("<groupSet><groupId>sg-0a1b2c3d4e5f60718</groupId></groupSet>");

        let placeholder = sg_body
            .trim_start_matches("<groupId>")
            .trim_end_matches("</groupId>")
            .to_string();
        assert!(placeholder.starts_with("sg-"), "got: {placeholder}");
        assert_ne!(placeholder, "sg-0a1b2c3d4e5f60718", "id was not scrubbed");
        assert!(instance_body.contains(&placeholder), "got: {instance_body}");
    }

    #[test]
    fn distinct_identifiers_stay_distinct() {
        let mut scrubber = Scrubber::new();
        let out = scrubber.scrub("sg-0a1b2c3d4e5f60718 sg-1111111111111111");
        let ids: Vec<&str> = out.split_whitespace().collect();
        assert_ne!(ids[0], ids[1], "distinct groups collapsed into one: {out}");
    }

    #[test]
    fn account_ids_and_arns_are_scrubbed() {
        let mut scrubber = Scrubber::new();
        let out = scrubber.scrub("arn:aws:iam::987654321098:instance-profile/app-role");
        assert!(!out.contains("987654321098"), "account id survived: {out}");
        // The profile *name* is meaningful to the diff and must survive.
        assert!(out.ends_with("instance-profile/app-role"), "got: {out}");
    }

    #[test]
    fn elbv2_arn_tail_is_scrubbed_but_name_and_account_are_handled_separately() {
        let mut scrubber = Scrubber::new();
        let out = scrubber.scrub(
            "<LoadBalancerArn>arn:aws:elasticloadbalancing:us-east-1:987654321098:\
             loadbalancer/app/my-alb/50dc6c495c0c9188</LoadBalancerArn>",
        );
        assert!(!out.contains("987654321098"), "account id survived: {out}");
        assert!(
            !out.contains("50dc6c495c0c9188"),
            "arn tail survived: {out}"
        );
        // The load balancer's *name* is meaningful to the diff (or will be,
        // once behavioral tracking exists) and must survive, same as a
        // security group's name.
        assert!(out.contains("loadbalancer/app/my-alb/"), "got: {out}");
    }

    #[test]
    fn account_placeholder_is_obviously_synthetic() {
        // Reviewability is the point: someone reading a committed recording
        // must be able to tell a placeholder from a real account id without
        // trusting that the scrubber ran. A plausible-looking id (AWS's
        // conventional 123456789012, say) fails that test even though it is
        // technically scrubbed.
        let mut scrubber = Scrubber::new();
        let out = scrubber.scrub("<ownerId>987654321098</ownerId>");
        assert!(out.contains("000000000000"), "got: {out}");
    }

    #[test]
    fn rule_semantics_are_preserved() {
        // Scrubbing 0.0.0.0 would turn "open to the world" into "open to one
        // host" — changing what the recording asserts about security posture.
        let mut scrubber = Scrubber::new();
        let out = scrubber.scrub("<cidrIp>0.0.0.0/0</cidrIp><privateIp>10.0.4.17</privateIp>");
        assert!(
            out.contains("0.0.0.0/0"),
            "world-open rule was mangled: {out}"
        );
        assert!(!out.contains("10.0.4.17"), "private ip survived: {out}");
    }
}
