//! SARIF 2.1.0 scaffolding shared by the tools (contract section 5). Each tool builds its own
//! `rules` and `results`; this wraps them and fixes the shared keys.

use crate::Score;
use serde_json::{json, Value};

pub const SCHEMA_URI: &str = "https://json.schemastore.org/sarif-2.1.0.json";
/// The `partialFingerprints` key carrying the finding fingerprint.
pub const FINGERPRINT_KEY: &str = "doctorFinding/v1";

/// `{"doctorFinding/v1": fingerprint}`, for a result's `partialFingerprints`.
pub fn partial_fingerprints(fingerprint: &str) -> Value {
    json!({ FINGERPRINT_KEY: fingerprint })
}

/// A SARIF log with one run; the run carries `properties.score`.
pub fn document(
    tool: &str,
    version: &str,
    information_uri: &str,
    rules: Vec<Value>,
    results: Vec<Value>,
    score: &Score,
) -> Value {
    json!({
        "$schema": SCHEMA_URI,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": tool, "version": version,
                                "informationUri": information_uri, "rules": rules}},
            "results": results,
            "properties": {"score": score},
        }],
    })
}
