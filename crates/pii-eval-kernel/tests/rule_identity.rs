//! The rule identities a revision-2 document states (contracts) must equal the
//! constants of the code that implements them (kernel). Contracts cannot depend
//! on the kernel, so the equality is pinned here (ADR 0008).

use pii_eval_contracts::{PROTOCOL_VERSION, ProtocolIdentity, ProtocolRules};
use pii_eval_kernel::{
    ACCOUNTING_PROTOCOL_REVISION, ACCOUNTING_RULE_ID, MATCHING_PROTOCOL_REVISION, MATCHING_RULE_ID,
    STATS_REVISION, STATS_RULE_ID,
};

#[test]
fn kernel_constants_equal_the_contract_identities() {
    let rules = ProtocolRules::CANONICAL_V2;
    assert_eq!(rules.matching.id.as_str(), MATCHING_RULE_ID);
    assert_eq!(rules.matching.revision, MATCHING_PROTOCOL_REVISION);
    assert_eq!(rules.accounting.id.as_str(), ACCOUNTING_RULE_ID);
    assert_eq!(rules.accounting.revision, ACCOUNTING_PROTOCOL_REVISION);
    assert_eq!(rules.statistics.id.as_str(), STATS_RULE_ID);
    assert_eq!(rules.statistics.revision, STATS_REVISION);
    // The protocol revision the kernel's matching and accounting belong to is
    // the revision the engine emits.
    assert_eq!(MATCHING_PROTOCOL_REVISION, PROTOCOL_VERSION);
    assert_eq!(ACCOUNTING_PROTOCOL_REVISION, PROTOCOL_VERSION);
    assert!(ProtocolIdentity::CANONICAL_V2.is_canonical());
    assert_eq!(ProtocolIdentity::CANONICAL_V2.rules, Some(rules));
}
