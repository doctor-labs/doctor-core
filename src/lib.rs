//! Shared `doctor/1` contract pieces. Per-tool score formulas and fingerprint inputs stay in each
//! tool; this crate holds only what is identical everywhere.

mod envelope;
mod exit;
mod sanitize;
pub mod sarif;
mod score;
mod severity;

pub use envelope::{
    BaselineCounts, BaselineState, Confidence, Envelope, Evidence, Finding, Location, LocationKind,
    SCHEMA,
};
pub use exit::ExitCode;
pub use sanitize::{sanitize, sanitize_spaced};
pub use score::{score_label, Score};
pub use severity::Severity;

use sha2::{Digest, Sha256};

/// Finding fingerprint: first 16 lowercase hex chars of `sha256(data)`. Each tool decides what
/// goes into `data` (rule id + stable location identity); the hashing and truncation are shared.
pub fn fingerprint(data: &[u8]) -> String {
    use std::fmt::Write;
    Sha256::digest(data)[..8]
        .iter()
        .fold(String::with_capacity(16), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

#[cfg(test)]
mod conformance;
