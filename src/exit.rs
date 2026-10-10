/// doctor/1 exit codes (contract section 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ExitCode {
    /// Ran; no finding at or above `--fail-on`.
    Ok = 0,
    /// Ran; at least one finding at or above `--fail-on`.
    Findings = 1,
    /// Usage error, bad input, or the tool could not run.
    Error = 2,
    /// `--baseline` given; at least one NEW finding at or above `--fail-on` (beats `Findings`).
    NewFindings = 3,
    /// Interrupted (SIGINT).
    Interrupted = 130,
}

impl ExitCode {
    pub const ALL: [ExitCode; 5] = [
        ExitCode::Ok,
        ExitCode::Findings,
        ExitCode::Error,
        ExitCode::NewFindings,
        ExitCode::Interrupted,
    ];

    pub const fn code(self) -> u8 {
        self as u8
    }
}
