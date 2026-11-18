// SPDX-License-Identifier: Apache-2.0

//! Drops hidden content from HTML mail before it becomes text.
//!
//! Covered: elements hidden by an inline `style` (`display:none`, `visibility:hidden`,
//! `font-size:0`, `opacity:0`, or a zero `height`/`max-height` with `overflow:hidden`) or the
//! `hidden` attribute, with everything inside them; CSS comments and character references in the
//! style are resolved first. Also `<script>`, `<style>`, `<head>` and `<template>` elements and
//! comments. Not covered: text hidden by a style sheet rule, by matching its background colour,
//! or by positioning it off screen.
//! An unclosed element of the same name inside a hidden one hides more than it should, which
//! fails safe.

/// Elements that never have a closing tag.
const VOID: [&str; 14] = [
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
    "track", "wbr",
];

/// Elements removed with their content, whatever their attributes.
const REMOVED: [&str; 4] = ["script", "style", "head", "template"];

/// `html` without hidden elements, scripts, style sheets, the head and comments.
pub(crate) fn drop_hidden(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut rest = html;
    // The hidden element being skipped and how many of its name are open inside it.
    let mut skipping: Option<(String, usize)> = None;
    while let Some(open) = rest.find('<') {
        if skipping.is_none() {
            out.push_str(&rest[..open]);
        }
        rest = &rest[open..];
        if let Some(after) = rest.strip_prefix("<!--") {
            rest = after.find("-->").map_or("", |end| &after[end + 3..]);
            continue;
        }
        let Some(end) = tag_end(rest) else {
            // An unfinished tag at the end of the input: keep it as text unless skipping.
            if skipping.is_none() {
                out.push_str(rest);
            }
            return out;
        };
        let tag = &rest[..=end];
        rest = &rest[end + 1..];
        let closing = tag.starts_with("</");
        let name = tag_name(tag);
        let void = tag.ends_with("/>") || VOID.contains(&name.as_str());
        if let Some((hidden, depth)) = &mut skipping {
            if *hidden == name && !void {
                if closing {
                    *depth -= 1;
                    if *depth == 0 {
                        skipping = None;
                    }
                } else {
                    *depth += 1;
                }
            }
            continue;
        }
        if closing {
            out.push_str(tag);
        } else if REMOVED.contains(&name.as_str()) {
            if !void {
                rest = after_closing_tag(rest, &name);
            }
        } else if is_hidden(tag) {
            if !void {
                skipping = Some((name, 1));
            }
        } else {
            out.push_str(tag);
        }
    }
    if skipping.is_none() {
        out.push_str(rest);
    }
    out
}

/// Index of the `>` that ends the tag at the start of `s`, skipping quoted attribute values.
fn tag_end(s: &str) -> Option<usize> {
    let mut quote = None;
    for (i, c) in s.char_indices() {
        match (quote, c) {
            (None, '>') => return Some(i),
            (None, '"' | '\'') => quote = Some(c),
            (Some(q), _) if q == c => quote = None,
            _ => {}
        }
    }
    None
}

/// The lower-case element name of a start or end tag.
fn tag_name(tag: &str) -> String {
    tag.trim_start_matches('<')
        .trim_start_matches('/')
        .chars()
        .take_while(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// `s` after the closing tag of `name`, or the empty string when it never closes.
fn after_closing_tag<'a>(s: &'a str, name: &str) -> &'a str {
    let lower = s.to_ascii_lowercase();
    let needle = format!("</{name}");
    let Some(start) = lower.find(&needle) else {
        return "";
    };
    let tail = &s[start..];
    tail.find('>').map_or("", |end| &tail[end + 1..])
}

/// Whether the start tag hides its element: a `hidden` attribute or a hiding inline style.
fn is_hidden(tag: &str) -> bool {
    attributes(tag)
        .iter()
        .any(|(name, value)| name == "hidden" || (name == "style" && hides(value)))
}

/// Whether an inline style hides what it applies to.
fn hides(style: &str) -> bool {
    let style = strip_css_comments(&decode_entities(style)).to_ascii_lowercase();
    let mut collapsed = false;
    let mut clipped = false;
    for declaration in style.split(';') {
        let Some((property, value)) = declaration.split_once(':') else {
            continue;
        };
        let value: String = value
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .replace("!important", "");
        match property.trim() {
            "display" if value == "none" => return true,
            "visibility" if value == "hidden" => return true,
            "font-size" | "opacity" if is_zero(&value) => return true,
            "height" | "max-height" => collapsed = is_zero(&value),
            "overflow" | "overflow-y" => clipped = value == "hidden",
            _ => {}
        }
    }
    collapsed && clipped
}

/// `text` with every `/* ... */` replaced by a space; an unclosed comment runs to the end.
fn strip_css_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("/*") {
        out.push_str(&rest[..start]);
        out.push(' ');
        rest = rest[start + 2..]
            .find("*/")
            .map_or("", |end| &rest[start + 2 + end + 2..]);
    }
    out.push_str(rest);
    out
}

/// `text` with numeric character references and the few named ones a style can use decoded.
fn decode_entities(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        rest = &rest[amp..];
        let decoded = rest.find(';').filter(|end| *end <= 10).and_then(|end| {
            let name = &rest[1..end];
            let c = match name {
                "colon" => Some(':'),
                "semi" => Some(';'),
                "amp" => Some('&'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                "lt" => Some('<'),
                "gt" => Some('>'),
                _ => name.strip_prefix('#').and_then(|digits| {
                    match digits.strip_prefix(['x', 'X']) {
                        Some(hex) => u32::from_str_radix(hex, 16),
                        None => digits.parse(),
                    }
                    .ok()
                    .and_then(char::from_u32)
                }),
            };
            c.map(|c| (c, end))
        });
        match decoded {
            Some((c, end)) => {
                out.push(c);
                rest = &rest[end + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Whether a CSS number is zero, with or without a unit (`0`, `0px`, `0.0em`, `0%`).
fn is_zero(value: &str) -> bool {
    let number = value.trim_end_matches(|c: char| c.is_ascii_alphabetic() || c == '%');
    !number.is_empty() && number.chars().all(|c| c == '0' || c == '.') && number != "."
}

/// The lower-case attribute names of a start tag with their values.
fn attributes(tag: &str) -> Vec<(String, String)> {
    let inner = tag.trim_start_matches('<').trim_end_matches('>');
    let inner = inner.trim_end_matches('/');
    let mut rest = inner.trim_start_matches(|c: char| !c.is_whitespace());
    let mut found = Vec::new();
    loop {
        rest = rest.trim_start_matches(|c: char| c.is_whitespace() || c == '/');
        if rest.is_empty() {
            return found;
        }
        let name_len = rest
            .find(|c: char| c.is_whitespace() || c == '=')
            .unwrap_or(rest.len());
        let name = rest[..name_len].to_ascii_lowercase();
        rest = rest[name_len..].trim_start();
        let mut value = String::new();
        if let Some(after) = rest.strip_prefix('=') {
            let after = after.trim_start();
            let (text, tail) = if let Some(q @ ('"' | '\'')) = after.chars().next() {
                let body = &after[1..];
                body.find(q)
                    .map_or((body, ""), |end| (&body[..end], &body[end + 1..]))
            } else {
                let end = after.find(char::is_whitespace).unwrap_or(after.len());
                (&after[..end], &after[end..])
            };
            value.push_str(text);
            rest = tail;
        }
        found.push((name, value));
    }
}

#[cfg(test)]
mod tests {
    use super::drop_hidden;

    #[test]
    fn hiding_styles_drop_the_element_and_what_is_inside_it() {
        for style in [
            "display:none",
            "DISPLAY : NONE !important",
            "color:red;visibility:hidden",
            "font-size:0",
            "font-size: 0.0em",
            "opacity:0",
            "display:/**/none",
            "display&#58;none",
            "display&colon;none",
            "display&#x3a;none",
            "display:&#110;one",
            "max-height:0;overflow:hidden",
            "overflow:hidden; MAX-HEIGHT: 0px !important",
            "height:0;overflow:hidden",
        ] {
            let html = format!("a<div style=\"{style}\">x<div>y</div>z</div>b");
            assert_eq!(drop_hidden(&html), "ab", "style {style:?}");
        }
    }

    #[test]
    fn visible_styles_and_other_attributes_stay() {
        for html in [
            "<p style=\"font-size:0.9em\">t</p>",
            "<p style=\"opacity:0.5;display:block\">t</p>",
            "<p style=\"max-height:0\">t</p>",
            "<p style=\"overflow:hidden;max-height:2em\">t</p>",
            "<p style=\"/* display:none */color:red\">t</p>",
            "<img alt=\"a hidden thing\" src=x>",
            "<p title='display:none'>t</p>",
        ] {
            assert_eq!(drop_hidden(html), html);
        }
    }

    #[test]
    fn script_style_head_template_and_comments_go() {
        let html = "1<head><title>t</title></head>2<script>if (a < b) { x('</p>') }</SCRIPT>3\
                    <style>p > a {}</style>4<template><p>t</p></template>5<!-- <p>c</p> -->6";
        assert_eq!(drop_hidden(html), "123456");
    }

    #[test]
    fn unfinished_input_does_not_panic() {
        for html in [
            "<div style=\"display:none",
            "a<",
            "<script>x",
            "<!-- x",
            "<div hidden>x",
        ] {
            let _ = drop_hidden(html);
        }
    }
}
