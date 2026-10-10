use serde::{Deserialize, Serialize};

/// The doctor/1 score object. The formula that produces `value` is the tool's own; `model` names it
/// (`<tool>/<n>`, bumped whenever the formula changes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Score {
    pub value: u8,
    pub label: String,
    pub model: String,
    pub coverage_gaps: usize,
}

impl Score {
    /// `value` is clamped to 100; `label` is derived by [`score_label`].
    pub fn new(value: u8, model: &str, coverage_gaps: usize) -> Self {
        let value = value.min(100);
        Score {
            value,
            label: score_label(value, coverage_gaps).to_string(),
            model: model.to_string(),
            coverage_gaps,
        }
    }
}

/// `good` (>= 90), `needs work` (>= 60), `critical`; `incomplete` replaces `good` on coverage gaps.
pub const fn score_label(value: u8, coverage_gaps: usize) -> &'static str {
    if value >= 90 {
        if coverage_gaps > 0 {
            "incomplete"
        } else {
            "good"
        }
    } else if value >= 60 {
        "needs work"
    } else {
        "critical"
    }
}
