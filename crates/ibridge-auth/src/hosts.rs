// SPDX-License-Identifier: Apache-2.0

//! iCloud hosts that may receive credentials.

/// Returns whether `host` is one of the six iCloud patterns.
///
/// A port, when present, must be 443. A hostname with no port is allowed so
/// IMAP can pass `imap.mail.me.com` without embedding its own port.
#[must_use]
pub fn is_allowed_host(host: &str) -> bool {
    if host.is_empty()
        || host.bytes().any(|byte| {
            byte.is_ascii_whitespace() || matches!(byte, b'@' | b'/' | b'\\' | b'?' | b'#')
        })
    {
        return false;
    }
    let name = if let Some((name, port)) = host.split_once(':') {
        if port != "443" || name.is_empty() {
            return false;
        }
        name
    } else {
        host
    };
    let name = name.to_ascii_lowercase();
    if name.ends_with('.') || name.starts_with('.') {
        return false;
    }
    matches!(
        name.as_str(),
        "imap.mail.me.com" | "smtp.mail.me.com" | "caldav.icloud.com" | "contacts.icloud.com"
    ) || is_shard(&name)
}

/// `p` + digits + `-caldav.icloud.com` or `-contacts.icloud.com`.
fn is_shard(name: &str) -> bool {
    let Some(rest) = name.strip_prefix('p') else {
        return false;
    };
    let Some((digits, suffix)) = rest.split_once('-') else {
        return false;
    };
    !digits.is_empty()
        && digits.bytes().all(|byte| byte.is_ascii_digit())
        && matches!(suffix, "caldav.icloud.com" | "contacts.icloud.com")
}
