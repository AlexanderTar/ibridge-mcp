// SPDX-License-Identifier: Apache-2.0

//! Strips hidden characters from mail, event and contact text.

/// Whether `c` is invisible or reorders text: Unicode tag characters, bidi overrides and
/// isolates, zero-width characters, the word joiner and the byte order mark.
const fn is_hidden(c: char) -> bool {
    matches!(
        c,
        '\u{E0000}'..='\u{E007F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
            | '\u{200B}'..='\u{200D}'
            | '\u{2060}'
            | '\u{FEFF}'
    )
}

/// Returns `text` without hidden characters. Ordinary text, newlines and tabs are kept.
#[must_use]
pub(crate) fn strip_hidden(text: &str) -> String {
    text.chars().filter(|c| !is_hidden(*c)).collect()
}

#[cfg(test)]
mod tests {
    use super::strip_hidden;

    #[test]
    fn hidden_characters_are_removed() {
        let hidden = "a\u{E0041}\u{E007F}b\u{202A}\u{202E}c\u{2066}\u{2069}d\u{200B}\u{200C}\u{200D}e\u{2060}f\u{FEFF}g";
        assert_eq!(strip_hidden(hidden), "abcdefg");
    }

    #[test]
    fn ordinary_text_newlines_and_tabs_are_kept() {
        let text = "Grüße, 世界 👍\n\tline two";
        assert_eq!(strip_hidden(text), text);
    }
}
