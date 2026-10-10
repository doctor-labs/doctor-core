//! Contract section 8. Covers C0/C1 controls (ESC), bidi controls, zero-width characters,
//! line/paragraph separators, plus the other invisible format characters.

fn invisible(c: char) -> bool {
    c.is_control()
        || matches!(c as u32,
            0xAD | 0x61C | 0x180E | 0x200B..=0x200F | 0x2028..=0x202E
            | 0x2060..=0x206F | 0xFEFF | 0xFFF9..=0xFFFB | 0xE0000..=0xE007F)
}

/// Remove invisible/control characters; any whitespace becomes a plain space.
pub fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .filter(|c| !invisible(*c))
        .collect()
}

/// Like [`sanitize`] but each invisible/control character becomes a space instead of vanishing
/// (keeps word boundaries and column widths).
pub fn sanitize_spaced(s: &str) -> String {
    s.chars()
        .map(|c| {
            if invisible(c) || c.is_whitespace() {
                ' '
            } else {
                c
            }
        })
        .collect()
}
