use crate::{Score, Severity};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// The `schema` value of every envelope.
pub const SCHEMA: &str = "doctor/1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Certain,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LocationKind {
    File,
    Flow,
    Frame,
    Image,
    CardPath,
    Device,
    Service,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    pub kind: LocationKind,
    #[serde(rename = "ref")]
    pub reference: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
}

impl Location {
    pub fn new(kind: LocationKind, reference: impl Into<String>) -> Self {
        Location {
            kind,
            reference: reference.into(),
            line: None,
            column: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    #[serde(rename = "ref")]
    pub reference: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BaselineState {
    New,
    Unchanged,
}

/// One finding (contract section 2). Unknown keys a tool adds go in `extra`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub fingerprint: String,
    pub severity: Severity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
    pub category: String,
    pub message: String,
    pub location: Location,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
    /// Serialized as `null` when there is no known fix.
    pub remedy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_state: Option<BaselineState>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Finding {
    /// Findings order: severity (critical first), then id, then fingerprint.
    pub fn sort(findings: &mut [Finding]) {
        findings.sort_by(|a, b| {
            (b.severity, &a.id, &a.fingerprint).cmp(&(a.severity, &b.id, &b.fingerprint))
        });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineCounts {
    pub new: usize,
    pub unchanged: usize,
    pub fixed: usize,
}

/// The `doctor/1` envelope (contract section 1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    pub schema: String,
    pub tool: String,
    pub version: String,
    pub exit_code: u8,
    pub score: Score,
    pub findings: Vec<Finding>,
    pub data: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline: Option<BaselineCounts>,
}

impl Envelope {
    pub fn new(
        tool: &str,
        version: &str,
        exit_code: u8,
        score: Score,
        findings: Vec<Finding>,
        data: Value,
    ) -> Self {
        Envelope {
            schema: SCHEMA.to_string(),
            tool: tool.to_string(),
            version: version.to_string(),
            exit_code,
            score,
            findings,
            data,
            baseline: None,
        }
    }

    /// As a JSON value (object keys come out sorted; order is not significant in the contract).
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).expect("envelope serializes")
    }
}
