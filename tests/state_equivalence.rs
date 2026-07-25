//! Cross-format equivalence: `terraform show -json` and the raw `.tfstate`
//! describe the same infrastructure, so both parsers must produce identical
//! resources.
//!
//! Both fixtures were captured from a *single* real `terraform apply`
//! (Terraform v1.9.8, `terraform_data` resources — a builtin, so no cloud
//! credentials are involved). The config deliberately covers the cases where
//! the two schemas diverge most: `count`, `for_each`, and a nested module,
//! none of which carry a precomputed address in raw state.
//!
//! This is the test that justifies feeding one diff engine from two parsers.

use uncia::Resource;

fn sorted(mut resources: Vec<Resource>) -> Vec<Resource> {
    resources.sort_by(|a, b| a.id.0.cmp(&b.id.0));
    resources
}

#[test]
fn both_parsers_agree_on_real_terraform_output() {
    let from_show =
        sorted(uncia::state::parse(include_str!("fixtures/equiv_show_json.json")).unwrap());
    let from_raw =
        sorted(uncia::state::parse(include_str!("fixtures/equiv_raw_tfstate.json")).unwrap());

    // Sanity: the fixtures actually contain the tricky cases.
    assert_eq!(from_show.len(), 6, "expected 6 resources in the fixture");

    let show_addresses: Vec<&str> = from_show.iter().map(|r| r.id.0.as_str()).collect();
    assert_eq!(
        show_addresses,
        [
            "module.network.terraform_data.inner",
            "terraform_data.counted[0]",
            "terraform_data.counted[1]",
            "terraform_data.keyed[\"blue\"]",
            "terraform_data.keyed[\"green\"]",
            "terraform_data.web",
        ]
    );

    // The equivalence itself: same addresses, kinds, and cloud ids.
    let raw_addresses: Vec<&str> = from_raw.iter().map(|r| r.id.0.as_str()).collect();
    assert_eq!(show_addresses, raw_addresses);

    for (show, raw) in from_show.iter().zip(from_raw.iter()) {
        assert_eq!(show.kind, raw.kind, "kind mismatch for {}", show.id.0);
        assert_eq!(
            show.cloud_id(),
            raw.cloud_id(),
            "cloud id mismatch for {}",
            show.id.0
        );
        assert!(
            show.cloud_id().is_some(),
            "{} should carry a cloud id",
            show.id.0
        );
    }
}

#[test]
fn dispatch_routes_both_document_kinds() {
    // Same entrypoint, no flag: the caller doesn't have to know which kind of
    // document they were handed.
    assert!(
        !uncia::state::parse(include_str!("fixtures/equiv_show_json.json"))
            .unwrap()
            .is_empty()
    );
    assert!(
        !uncia::state::parse(include_str!("fixtures/equiv_raw_tfstate.json"))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn dispatch_still_rejects_wrong_documents() {
    use uncia::UnciaError;

    // Guards must run before routing, not after.
    assert!(matches!(
        uncia::state::parse(include_str!("fixtures/encrypted_tofu.json")).unwrap_err(),
        UnciaError::EncryptedState
    ));
    assert!(matches!(
        uncia::state::parse(include_str!("fixtures/plan_output.json")).unwrap_err(),
        UnciaError::WrongDocumentKind { .. }
    ));
    assert!(matches!(
        uncia::state::parse("{}").unwrap_err(),
        UnciaError::UnsupportedFormatVersion { .. }
    ));
    assert!(matches!(
        uncia::state::parse("not json").unwrap_err(),
        UnciaError::StateJson(_)
    ));
}
