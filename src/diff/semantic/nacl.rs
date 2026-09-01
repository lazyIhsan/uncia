//! Network-ACL rule evaluation: given an ordered set of entries and one
//! candidate flow, does the NACL allow or deny it — independent of any
//! single [`super::Relation`], the same shape [`super::reachability`] takes
//! for the security-group trust walk.
//!
//! **Why this exists.** `ARCHITECTURE.md`'s expansion path names the gap:
//! *"a security-group rule can be declared correctly and still not matter
//! if a NACL blocks it."* A security group is an allow-list with no
//! ordering — every matching rule applies. A network ACL is the opposite: an
//! **ordered**, first-match-wins list of `allow`/`deny` rules, evaluated at
//! the subnet boundary regardless of what any attached security group says.
//! Answering "is this actually reachable" needs both, and this is the piece
//! that reasons about the second one in isolation, pure and unit-testable
//! against hand-built rule sets before any relation composes it.
//!
//! **Deliberately literal, not CIDR-range arithmetic.** `source_cidr` is
//! matched by exact string equality against each rule's `cidr_block` /
//! `ipv6_cidr_block` — not "does this rule's range contain that address."
//! The one caller this exists for only ever asks about the internet as a
//! whole (`0.0.0.0/0` / `::/0`, the same literal constants
//! `reachability::INTERNET_CIDRS` restricts itself to, for the same
//! reason: `1.2.3.0/24` being "basically the internet" is a judgment call
//! this does not make). A NACL rule scoped to some narrower range isn't
//! answering the same question a `0.0.0.0/0` query asks, so it's correctly
//! excluded rather than approximated as a partial match.
//!
//! **No ICMP type/code matching.** Only protocol and port range are
//! evaluated; an ICMP rule's `icmp_type`/`icmp_code` are read by the
//! collector but not consulted here. Known gap, not a silent one — nothing
//! in this codebase's security-group side models ICMP type/code either, so
//! there is no caller yet that could supply them.
//!
//! **A query is a port *range*, matched by full containment.** The
//! security-group rule that establishes reachability can open a range
//! (`1024-65535`, not just one port), so a query asks "does this NACL allow
//! the *entire* range," not "does some port in it happen to match." A NACL
//! rule matches only when its own range fully contains the query's — the
//! same literal, no-partial-credit philosophy as the CIDR match above. A
//! query answered only by *several* NACL rules together, each covering part
//! of the range, is not currently detected as a match; that would be
//! genuine range-union arithmetic, not a literal check, and there is no
//! caller yet that needs it.

use serde_json::Value;

/// The outcome of evaluating one candidate flow against a NACL's ordered
/// entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    /// Either an explicit `deny` rule matched, or nothing did — AWS treats
    /// unmatched traffic as denied at the subnet boundary, and so does this.
    Deny,
}

/// Evaluate `entries` — one NACL direction's `ingress` or `egress` array, in
/// the shape `collector::aws::network_acl` normalizes — against a flow from
/// `source_cidr` on `protocol` (the NACL API's own
/// protocol-*number* string convention: `"-1"`, `"6"` for tcp, `"17"` for
/// udp, ...) spanning `port_from..=port_to` (equal for a single port).
///
/// Rules are considered in ascending `rule_no` order and the first match
/// wins, mirroring AWS's own evaluation order exactly. No match is implicit
/// deny.
pub fn evaluate(
    entries: &[Value],
    source_cidr: &str,
    protocol: &str,
    port_from: i64,
    port_to: i64,
) -> Verdict {
    let winner = entries
        .iter()
        .filter(|e| rule_source_matches(e, source_cidr))
        .filter(|e| rule_protocol_matches(e, protocol))
        .filter(|e| rule_port_matches(e, port_from, port_to))
        .filter_map(|e| {
            let rule_no = e.get("rule_no").and_then(Value::as_i64)?;
            let action = e.get("action").and_then(Value::as_str)?;
            Some((rule_no, action))
        })
        .min_by_key(|(rule_no, _)| *rule_no);

    match winner {
        Some((_, "allow")) => Verdict::Allow,
        _ => Verdict::Deny,
    }
}

fn rule_source_matches(entry: &Value, source_cidr: &str) -> bool {
    let cidr = entry
        .get("cidr_block")
        .and_then(Value::as_str)
        .unwrap_or("");
    let cidr6 = entry
        .get("ipv6_cidr_block")
        .and_then(Value::as_str)
        .unwrap_or("");
    cidr == source_cidr || cidr6 == source_cidr
}

/// `"-1"` (all protocols) matches any query protocol, and vice versa — a
/// query asking about `"-1"` (an SG rule with no specific protocol) is only
/// answered by a NACL rule that is itself unrestricted.
fn rule_protocol_matches(entry: &Value, protocol: &str) -> bool {
    let rule_protocol = entry.get("protocol").and_then(Value::as_str).unwrap_or("");
    rule_protocol == "-1" || protocol == "-1" || rule_protocol == protocol
}

/// A protocol-`"-1"` rule carries no real port range — `network_acl.rs`
/// normalizes its absent `from_port`/`to_port` to `0`/`0`, which would
/// wrongly exclude every port if treated as a literal range here.
///
/// Containment, not overlap: the rule's own range must cover the *entire*
/// `port_from..=port_to` query, not just intersect it.
fn rule_port_matches(entry: &Value, port_from: i64, port_to: i64) -> bool {
    if entry.get("protocol").and_then(Value::as_str) == Some("-1") {
        return true;
    }
    let from = entry.get("from_port").and_then(Value::as_i64).unwrap_or(0);
    let to = entry.get("to_port").and_then(Value::as_i64).unwrap_or(0);
    from <= port_from && port_to <= to
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rule(rule_no: i64, action: &str, protocol: &str, cidr: &str, from: i64, to: i64) -> Value {
        json!({
            "rule_no": rule_no, "action": action, "protocol": protocol,
            "cidr_block": cidr, "ipv6_cidr_block": "",
            "from_port": from, "to_port": to,
            "icmp_type": 0, "icmp_code": 0,
        })
    }

    fn ipv6_rule(
        rule_no: i64,
        action: &str,
        protocol: &str,
        cidr6: &str,
        from: i64,
        to: i64,
    ) -> Value {
        json!({
            "rule_no": rule_no, "action": action, "protocol": protocol,
            "cidr_block": "", "ipv6_cidr_block": cidr6,
            "from_port": from, "to_port": to,
            "icmp_type": 0, "icmp_code": 0,
        })
    }

    #[test]
    fn an_explicit_allow_rule_matching_the_flow_allows_it() {
        let entries = vec![rule(100, "allow", "6", "0.0.0.0/0", 443, 443)];
        assert_eq!(
            evaluate(&entries, "0.0.0.0/0", "6", 443, 443),
            Verdict::Allow
        );
    }

    #[test]
    fn an_explicit_deny_rule_matching_the_flow_denies_it() {
        let entries = vec![rule(100, "deny", "6", "0.0.0.0/0", 443, 443)];
        assert_eq!(
            evaluate(&entries, "0.0.0.0/0", "6", 443, 443),
            Verdict::Deny
        );
    }

    #[test]
    fn no_matching_rule_is_implicit_deny() {
        let entries = vec![rule(100, "allow", "6", "0.0.0.0/0", 22, 22)];
        // Port 443 matches no rule at all.
        assert_eq!(
            evaluate(&entries, "0.0.0.0/0", "6", 443, 443),
            Verdict::Deny
        );
    }

    #[test]
    fn an_empty_rule_set_is_implicit_deny() {
        assert_eq!(evaluate(&[], "0.0.0.0/0", "6", 443, 443), Verdict::Deny);
    }

    #[test]
    fn the_lowest_rule_number_wins_even_when_declared_out_of_order() {
        // rule_no 200 (broader allow) is declared first in the slice, but
        // rule_no 100 (a narrower deny) must still win: AWS evaluates by
        // rule_no, not declaration order.
        let entries = vec![
            rule(200, "allow", "-1", "0.0.0.0/0", 0, 0),
            rule(100, "deny", "6", "0.0.0.0/0", 443, 443),
        ];
        assert_eq!(
            evaluate(&entries, "0.0.0.0/0", "6", 443, 443),
            Verdict::Deny
        );
    }

    #[test]
    fn a_lower_numbered_rule_for_a_different_flow_does_not_shadow_a_later_match() {
        let entries = vec![
            rule(100, "deny", "6", "0.0.0.0/0", 22, 22),
            rule(200, "allow", "6", "0.0.0.0/0", 443, 443),
        ];
        // Rule 100 doesn't match (wrong port), so rule 200 is the real
        // first match, not an implicit deny.
        assert_eq!(
            evaluate(&entries, "0.0.0.0/0", "6", 443, 443),
            Verdict::Allow
        );
    }

    #[test]
    fn protocol_all_matches_any_protocol_and_ignores_the_placeholder_port_range() {
        // A "-1" rule normalizes from_port/to_port to 0/0 (network_acl.rs);
        // that must not be read as "only port 0".
        let entries = vec![rule(100, "allow", "-1", "0.0.0.0/0", 0, 0)];
        assert_eq!(
            evaluate(&entries, "0.0.0.0/0", "6", 443, 443),
            Verdict::Allow
        );
        assert_eq!(
            evaluate(&entries, "0.0.0.0/0", "17", 53, 53),
            Verdict::Allow
        );
    }

    #[test]
    fn a_query_for_protocol_all_only_matches_an_unrestricted_rule() {
        let entries = vec![rule(100, "allow", "6", "0.0.0.0/0", 443, 443)];
        // The rule only covers tcp/443, not "every protocol".
        assert_eq!(evaluate(&entries, "0.0.0.0/0", "-1", 0, 0), Verdict::Deny);
    }

    #[test]
    fn a_narrower_cidr_does_not_match_an_internet_wide_query() {
        // The literal-match philosophy: 10.0.0.0/8 is not "close enough" to
        // 0.0.0.0/0, even though every address in it is technically
        // contained in the wider range.
        let entries = vec![rule(100, "allow", "6", "10.0.0.0/8", 443, 443)];
        assert_eq!(
            evaluate(&entries, "0.0.0.0/0", "6", 443, 443),
            Verdict::Deny
        );
    }

    #[test]
    fn an_ipv6_rule_matches_the_ipv6_literal_source() {
        let entries = vec![ipv6_rule(100, "allow", "6", "::/0", 443, 443)];
        assert_eq!(evaluate(&entries, "::/0", "6", 443, 443), Verdict::Allow);
        // The ipv4 query gets no match from an ipv6-only rule.
        assert_eq!(
            evaluate(&entries, "0.0.0.0/0", "6", 443, 443),
            Verdict::Deny
        );
    }

    #[test]
    fn a_port_within_a_ranged_rule_matches() {
        let entries = vec![rule(100, "allow", "6", "0.0.0.0/0", 1024, 65535)];
        assert_eq!(
            evaluate(&entries, "0.0.0.0/0", "6", 8080, 8080),
            Verdict::Allow
        );
    }

    #[test]
    fn a_port_outside_the_ranged_rule_does_not_match() {
        let entries = vec![rule(100, "allow", "6", "0.0.0.0/0", 1024, 65535)];
        assert_eq!(evaluate(&entries, "0.0.0.0/0", "6", 80, 80), Verdict::Deny);
    }

    #[test]
    fn a_query_range_fully_contained_in_the_rules_range_matches() {
        let entries = vec![rule(100, "allow", "6", "0.0.0.0/0", 1024, 65535)];
        // The query's own range (a ranged SG rule, not a single port) must
        // be fully covered by the NACL rule to match.
        assert_eq!(
            evaluate(&entries, "0.0.0.0/0", "6", 8000, 9000),
            Verdict::Allow
        );
    }

    #[test]
    fn a_query_range_only_partially_covered_does_not_match() {
        // The NACL rule covers 1024-65535; the query asks about 80-443,
        // which only partially overlaps (443 is inside, 80 is not). Partial
        // coverage is not containment, so this is not a match - the same
        // no-partial-credit philosophy as the CIDR match.
        let entries = vec![rule(100, "allow", "6", "0.0.0.0/0", 1024, 65535)];
        assert_eq!(evaluate(&entries, "0.0.0.0/0", "6", 80, 443), Verdict::Deny);
    }
}
