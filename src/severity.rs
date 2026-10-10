use serde::{Deserialize, Serialize};

/// Finding severity. Ordered `Info < Low < Medium < High < Critical`; serializes lowercase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const ALL: [Severity; 5] = [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// Parse a doctor/1 severity name (exact lowercase).
    pub fn parse(s: &str) -> Option<Severity> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }

    /// Like [`Severity::parse`], also accepting the pre-doctor/1 vocabulary:
    /// `error` -> critical, `warn` -> low.
    pub fn parse_legacy(s: &str) -> Option<Severity> {
        match s {
            "error" => Some(Severity::Critical),
            "warn" => Some(Severity::Low),
            _ => Self::parse(s),
        }
    }

    /// SARIF result level: critical/high -> error, medium -> warning, low/info -> note.
    pub fn sarif_level(self) -> &'static str {
        match self {
            Severity::Critical | Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low | Severity::Info => "note",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
