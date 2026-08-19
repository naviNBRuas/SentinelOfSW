use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TargetType {
    Ip(IpAddr),
    Domain(String),
    Url(String),
    Cidr(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub raw: String,
    pub target_type: TargetType,
    pub display: String,
    pub normalized: String,
}

impl Target {
    pub fn detect(raw: &str) -> Self {
        let input = raw.trim().to_lowercase();

        if input.contains("://") {
            let host = input
                .split("://")
                .nth(1)
                .and_then(|s| s.split('/').next())
                .unwrap_or(&input);
            let display = host.to_string();
            let normalized = strip_common_ports(host);
            return Self {
                raw: input.clone(),
                target_type: TargetType::Url(input),
                display,
                normalized,
            };
        }

        if input.contains('/') {
            return Self {
                raw: input.clone(),
                target_type: TargetType::Cidr(input.clone()),
                display: input.clone(),
                normalized: input,
            };
        }

        if let Ok(ip) = IpAddr::from_str(&input) {
            return Self {
                raw: input.clone(),
                target_type: TargetType::Ip(ip),
                display: input.clone(),
                normalized: input,
            };
        }

        Self {
            raw: input.clone(),
            target_type: TargetType::Domain(input.clone()),
            display: input.clone(),
            normalized: input,
        }
    }

    /// Expand a CIDR notation into a list of individual IPs.
    /// Returns `None` if the target is not a CIDR or parsing fails.
    pub fn expand_cidr(&self) -> Option<Vec<String>> {
        match &self.target_type {
            TargetType::Cidr(cidr) => expand_cidr_str(cidr),
            _ => None,
        }
    }

    /// Return a list of target strings to scan.
    /// For CIDR, this expands to all hosts in the range.
    /// For single IP/domain, returns just `[normalized]`.
    pub fn hosts(&self) -> Vec<String> {
        if let Some(hosts) = self.expand_cidr() {
            hosts
        } else {
            vec![self.normalized.clone()]
        }
    }
}

/// Expand "10.10.10.0/24" into all 256 addresses, etc.
pub fn expand_cidr_str(cidr: &str) -> Option<Vec<String>> {
    let (ip_str, bits_str) = cidr.split_once('/')?;
    let prefix: u8 = bits_str.parse().ok()?;
    if prefix > 32 {
        return None;
    }
    let ip: Ipv4Addr = ip_str.parse().ok()?;
    let raw = u32::from(ip);
    let shift = 32 - prefix;
    let mask = if shift == 32 { 0 } else { !0u32 << shift };
    let base = raw & mask;

    let count = 1u32 << shift;
    // Cap at /16 (65536 hosts) — above that, warn and return None
    if count > 65536 {
        return None;
    }

    Some(
        (0..count)
            .map(|i| Ipv4Addr::from(base | i).to_string())
            .collect(),
    )
}

fn strip_common_ports(host: &str) -> String {
    let parts: Vec<&str> = host.split(':').collect();
    if parts.len() == 2 {
        match parts[1] {
            "80" | "443" | "8080" | "8443" => parts[0].to_string(),
            _ => host.to_string(),
        }
    } else {
        host.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_detect_ip() {
        let t = Target::detect("10.10.10.10");
        assert!(matches!(t.target_type, TargetType::Ip(_)));
        assert_eq!(t.normalized, "10.10.10.10");
    }

    #[test]
    fn test_detect_ipv6() {
        let t = Target::detect("::1");
        assert!(matches!(t.target_type, TargetType::Ip(_)));
    }

    #[test]
    fn test_detect_domain() {
        let t = Target::detect("google.com");
        assert!(matches!(t.target_type, TargetType::Domain(_)));
        assert_eq!(t.normalized, "google.com");
    }

    #[test]
    fn test_detect_url() {
        let t = Target::detect("https://example.com/admin");
        assert!(matches!(t.target_type, TargetType::Url(_)));
        assert_eq!(t.normalized, "example.com");
    }

    #[test]
    fn test_detect_cidr() {
        let t = Target::detect("10.10.10.0/24");
        assert!(matches!(t.target_type, TargetType::Cidr(_)));
        assert_eq!(t.normalized, "10.10.10.0/24");
    }

    #[test]
    fn test_strip_common_ports_http() {
        let t = Target::detect("http://google.com:80");
        assert_eq!(t.normalized, "google.com");
    }

    #[test]
    fn test_strip_common_ports_https() {
        let t = Target::detect("https://example.com:443");
        assert_eq!(t.normalized, "example.com");
    }

    #[test]
    fn test_keep_uncommon_port() {
        let t = Target::detect("http://example.com:8080");
        assert_eq!(t.normalized, "example.com");
    }

    #[test]
    fn test_keep_unusual_port() {
        let t = Target::detect("https://example.com:9999");
        assert_eq!(t.normalized, "example.com:9999");
    }

    #[test]
    fn test_url_with_path_and_query() {
        let t = Target::detect("https://example.com/path?q=1");
        assert!(matches!(t.target_type, TargetType::Url(_)));
        assert_eq!(t.normalized, "example.com");
    }

    #[test]
    fn test_ip_type_value() {
        let t = Target::detect("192.168.1.1");
        if let TargetType::Ip(ip) = t.target_type {
            assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        } else {
            panic!("Expected Ip");
        }
    }

    #[test]
    fn test_domain_display_matches_raw() {
        let t = Target::detect("sub.example.com");
        assert_eq!(t.display, "sub.example.com");
        assert_eq!(t.raw, "sub.example.com");
    }

    #[test]
    fn test_trim_whitespace() {
        let t = Target::detect("  10.10.10.10  ");
        assert!(matches!(t.target_type, TargetType::Ip(_)));
    }

    #[test]
    fn test_target_partial_eq() {
        let t1 = Target::detect("10.10.10.10");
        let t2 = Target::detect("10.10.10.10");
        assert_eq!(t1.target_type, t2.target_type);
        assert_eq!(t1.normalized, t2.normalized);
    }

    #[test]
    fn test_cidr_expand_24() {
        let hosts = expand_cidr_str("10.10.10.0/24").unwrap();
        assert_eq!(hosts.len(), 256);
        assert_eq!(hosts[0], "10.10.10.0");
        assert_eq!(hosts[1], "10.10.10.1");
        assert_eq!(hosts[255], "10.10.10.255");
    }

    #[test]
    fn test_cidr_expand_28() {
        let hosts = expand_cidr_str("192.168.1.0/28").unwrap();
        assert_eq!(hosts.len(), 16);
        assert_eq!(hosts[0], "192.168.1.0");
        assert_eq!(hosts[15], "192.168.1.15");
    }

    #[test]
    fn test_cidr_expand_32() {
        let hosts = expand_cidr_str("10.0.0.1/32").unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0], "10.0.0.1");
    }

    #[test]
    fn test_cidr_expand_16() {
        let hosts = expand_cidr_str("10.0.0.0/16").unwrap();
        assert_eq!(hosts.len(), 65536);
        assert_eq!(hosts[0], "10.0.0.0");
        assert_eq!(hosts[65535], "10.0.255.255");
    }

    #[test]
    fn test_cidr_too_large() {
        let hosts = expand_cidr_str("10.0.0.0/8");
        assert!(hosts.is_none());
    }

    #[test]
    fn test_cidr_invalid_ip() {
        let hosts = expand_cidr_str("not-an-ip/24");
        assert!(hosts.is_none());
    }

    #[test]
    fn test_cidr_invalid_prefix() {
        let hosts = expand_cidr_str("10.0.0.0/33");
        assert!(hosts.is_none());
    }

    #[test]
    fn test_cidr_no_slash() {
        let hosts = expand_cidr_str("10.0.0.0");
        assert!(hosts.is_none());
    }

    #[test]
    fn test_hosts_returns_single_for_ip() {
        let t = Target::detect("10.10.10.10");
        let hosts = t.hosts();
        assert_eq!(hosts, vec!["10.10.10.10"]);
    }

    #[test]
    fn test_hosts_expands_cidr() {
        let t = Target::detect("10.10.10.0/30");
        let hosts = t.hosts();
        assert_eq!(hosts.len(), 4);
        assert_eq!(hosts[0], "10.10.10.0");
        assert_eq!(hosts[3], "10.10.10.3");
    }
}
