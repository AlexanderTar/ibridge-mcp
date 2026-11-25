// SPDX-License-Identifier: Apache-2.0

//! Which addresses a one-click unsubscribe may connect to.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Decides whether `address` may be connected to. The production policy is [`is_public`].
pub(crate) type AddressPolicy = fn(IpAddr) -> bool;

/// Whether `address` is a public unicast address.
///
/// Refuses loopback, private (RFC 1918, ULA), link-local, carrier-grade NAT, unspecified,
/// multicast, broadcast, reserved and documentation ranges. An IPv6 address that embeds an
/// IPv4 one (mapped, compatible, NAT64, 6to4) is judged by the IPv4 address inside it.
/// IPv6 must be global unicast (`2000::/3`).
pub(crate) fn is_public(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    !(a == 0                                   // 0.0.0.0/8, unspecified
        || a == 10                             // RFC 1918
        || (a == 100 && (64..=127).contains(&b)) // 100.64.0.0/10, carrier-grade NAT
        || a == 127                            // loopback
        || (a == 169 && b == 254)              // link-local
        || (a == 172 && (16..=31).contains(&b)) // RFC 1918
        || (a == 192 && b == 0 && c == 0)      // 192.0.0.0/24, IETF protocol assignments
        || (a == 192 && b == 0 && c == 2)      // documentation
        || (a == 192 && b == 88 && c == 99)    // 6to4 relay anycast
        || (a == 192 && b == 168)              // RFC 1918
        || (a == 198 && (b == 18 || b == 19))  // benchmarking
        || (a == 198 && b == 51 && c == 100)   // documentation
        || (a == 203 && b == 0 && c == 113)    // documentation
        || a >= 224) // multicast, reserved and broadcast
}

fn is_public_v6(address: Ipv6Addr) -> bool {
    let [s0, s1, s2, s3, s4, s5, s6, s7] = address.segments();
    let embedded = |high: u16, low: u16| {
        let [a, b] = high.to_be_bytes();
        let [c, d] = low.to_be_bytes();
        is_public_v4(Ipv4Addr::new(a, b, c, d))
    };
    // NAT64 (64:ff9b::/96) carries an IPv4 address in its last 32 bits. Mapped
    // (::ffff:0:0/96) and compatible (::/96) forms fall outside 2000::/3 and are refused.
    if (s0, s1, s2, s3, s4, s5) == (0x0064, 0xff9b, 0, 0, 0, 0) {
        return embedded(s6, s7);
    }
    // Everything else must be global unicast, minus the ranges inside it that are not public.
    if s0 & 0xe000 != 0x2000 {
        return false;
    }
    match (s0, s1) {
        // 6to4: the IPv4 address sits in bits 16..48.
        (0x2002, _) => embedded(s1, s2),
        // 2001::/23 IETF protocol assignments (Teredo among them); 2001:db8::/32 documentation.
        (0x2001, s1) => s1 >= 0x0200 && s1 != 0x0db8,
        // 3fff::/20 documentation.
        (0x3fff, s1) => s1 >= 0x1000,
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::is_public;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("test address")
    }

    #[test]
    fn refuses_every_non_public_ipv4_range() {
        for text in [
            "0.0.0.0",
            "0.1.2.3",
            "10.0.0.1",
            "10.255.255.255",
            "100.64.0.1",
            "100.127.255.254",
            "127.0.0.1",
            "127.255.255.254",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.1",
            "192.0.2.7",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.19.255.255",
            "198.51.100.9",
            "203.0.113.9",
            "224.0.0.1",
            "239.255.255.255",
            "240.0.0.1",
            "255.255.255.255",
        ] {
            assert!(!is_public(ip(text)), "{text} must be refused");
        }
    }

    #[test]
    fn allows_public_ipv4() {
        for text in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "100.63.255.255",
            "100.128.0.1",
            "172.15.255.255",
            "172.32.0.1",
            "198.17.255.255",
            "198.20.0.1",
            "223.255.255.255",
        ] {
            assert!(is_public(ip(text)), "{text} must be allowed");
        }
    }

    #[test]
    fn refuses_every_non_public_ipv6_range() {
        for text in [
            "::",
            "::1",
            "::2",
            "fc00::1",
            "fd12:3456:789a::1",
            "fe80::1",
            "febf::1",
            "fec0::1",
            "ff02::1",
            "ff0e::1",
            "2001:db8::1",
            "3fff::1",
            "100::1",
            "2001::1",
            "2001:2::1",
            "5f00::1",
            "4000::1",
            "8000::1",
        ] {
            assert!(!is_public(ip(text)), "{text} must be refused");
        }
    }

    #[test]
    fn refuses_ipv6_forms_that_carry_a_private_ipv4() {
        for text in [
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:192.168.0.1",
            "::ffff:169.254.169.254",
            "::ffff:0.0.0.0",
            "::ffff:8.8.8.8",
            "::127.0.0.1",
            "::8.8.8.8",
            "64:ff9b::7f00:1",
            "64:ff9b::a00:1",
            "64:ff9b::c0a8:1",
            "64:ff9b:1::1",
            "2002:7f00:1::1",
            "2002:a00:1::1",
            "2002:c0a8:101::1",
            "2002:a9fe:a9fe::1",
        ] {
            assert!(!is_public(ip(text)), "{text} must be refused");
        }
    }

    #[test]
    fn allows_public_ipv6_and_public_ipv4_inside_nat64_and_6to4() {
        for text in [
            "2606:4700:4700::1111",
            "2a00:1450:4001:81b::200e",
            "2001:4860:4860::8888",
            "64:ff9b::808:808",
            "2002:808:808::1",
        ] {
            assert!(is_public(ip(text)), "{text} must be allowed");
        }
    }
}
