use crate::config::{Action, ListFormat};
use crate::rules::Rules;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IpNet {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl IpNet {
    pub fn contains(&self, candidate: IpAddr) -> bool {
        if self.prefix == 0 {
            return matches!(
                (self.addr, candidate),
                (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
            );
        }
        match (self.addr, candidate) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let shift = 32u32.saturating_sub(self.prefix as u32);
                if shift == 0 {
                    return net == ip;
                }
                let mask = u32::MAX << shift;
                (u32::from(net) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let shift = 128u32.saturating_sub(self.prefix as u32);
                if shift == 0 {
                    return net == ip;
                }
                let mask = u128::MAX << shift;
                (u128::from(net) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ParsedList {
    pub domains: HashSet<String>,
    pub ips: Vec<IpNet>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainMatch {
    Allow,
    Block,
}

#[derive(Clone, Debug, Default)]
pub struct DomainIndex {
    pub block: HashSet<String>,
    pub allow: HashSet<String>,
    pub ip_block: Vec<IpNet>,
    pub ip_allow: Vec<IpNet>,
}

impl DomainIndex {
    pub fn domain_match(&self, domain: &str) -> Option<DomainMatch> {
        if self.allow.is_empty() && self.block.is_empty() {
            return None;
        }
        let mut suffixes: Vec<String> = Vec::new();
        let mut suffix = String::new();
        for label in domain.rsplit('.') {
            suffix = if suffix.is_empty() {
                label.to_string()
            } else {
                format!("{label}.{suffix}")
            };
            suffixes.push(suffix.clone());
        }
        if suffixes.iter().any(|s| self.allow.contains(s)) {
            return Some(DomainMatch::Allow);
        }
        if suffixes.iter().any(|s| self.block.contains(s)) {
            return Some(DomainMatch::Block);
        }
        None
    }

    pub fn ip_match(&self, ip: IpAddr) -> Option<DomainMatch> {
        if self.ip_allow.iter().any(|net| net.contains(ip)) {
            return Some(DomainMatch::Allow);
        }
        if self.ip_block.iter().any(|net| net.contains(ip)) {
            return Some(DomainMatch::Block);
        }
        None
    }
}

pub fn build_index(lists: &[(bool, Action, ParsedList)], rules: &Rules) -> DomainIndex {
    let mut index = DomainIndex::default();
    let mut seen_ips: HashSet<IpNet> = HashSet::new();
    for (enabled, action, parsed) in lists {
        if !*enabled {
            continue;
        }
        match action {
            Action::Block => {
                for domain in &parsed.domains {
                    index.block.insert(domain.clone());
                }
                for ip in &parsed.ips {
                    if seen_ips.insert(*ip) {
                        index.ip_block.push(*ip);
                    }
                }
            }
            Action::Allow => {
                for domain in &parsed.domains {
                    index.allow.insert(domain.clone());
                }
                for ip in &parsed.ips {
                    if seen_ips.insert(*ip) {
                        index.ip_allow.push(*ip);
                    }
                }
            }
        }
    }

    // Unbreak lists lift matching list blocks, but never user-defined rules.
    index.block.retain(|domain| !index.allow.contains(domain));
    index
        .ip_block
        .retain(|network| !index.ip_allow.contains(network));

    for domain in &rules.custom_block {
        if let Some(domain) = normalize_domain(domain) {
            index.block.insert(domain.clone());
            index.allow.remove(&domain);
        }
    }
    for domain in &rules.custom_allow {
        if let Some(domain) = normalize_domain(domain) {
            index.allow.insert(domain);
        }
    }
    for entry in &rules.ip_block {
        if let Some(net) = parse_ip_net(entry) {
            if seen_ips.insert(net) {
                index.ip_block.push(net);
            }
            index.ip_allow.retain(|allowed| *allowed != net);
        }
    }
    for entry in &rules.ip_allow {
        if let Some(net) = parse_ip_net(entry) {
            index.ip_allow.push(net);
        }
    }
    index
}

pub fn normalize_domain(raw: &str) -> Option<String> {
    let mut candidate = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if candidate.starts_with("*.") {
        candidate = candidate[2..].to_string();
    }
    if candidate.is_empty() || candidate.len() > 253 {
        return None;
    }
    if candidate.contains('/') || candidate.contains(':') || candidate.contains(' ') {
        return None;
    }
    let labels: Vec<&str> = candidate.split('.').collect();
    if labels.is_empty() {
        return None;
    }
    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        if !label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return None;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return None;
        }
    }
    Some(candidate)
}

fn strip_comment(line: &str) -> &str {
    let line = line.trim();
    if line.is_empty()
        || line.starts_with('#')
        || line.starts_with('!')
        || line.starts_with("//")
    {
        return "";
    }
    line
}

pub fn parse_ip_net(raw: &str) -> Option<IpNet> {
    let raw = raw.trim();
    let (addr_text, prefix_text) = match raw.split_once('/') {
        Some((addr, prefix)) => (addr, Some(prefix)),
        None => (raw, None),
    };
    let addr: IpAddr = addr_text.parse().ok()?;
    let max_prefix = if addr.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix_text {
        Some(prefix) => prefix.parse::<u8>().ok()?,
        None => max_prefix,
    };
    if prefix > max_prefix {
        return None;
    }
    Some(IpNet { addr, prefix })
}

fn domain_from_token(token: &str) -> Option<String> {
    normalize_domain(token)
}

pub fn parse_list(text: &str, format: ListFormat) -> ParsedList {
    let mut parsed = ParsedList::default();
    let mut seen_ips: HashSet<IpNet> = HashSet::new();
    for raw_line in text.lines() {
        let line = strip_comment(raw_line);
        if line.is_empty() {
            continue;
        }
        match format {
            ListFormat::Hosts => {
                let mut parts = line.split_whitespace();
                let first = parts.next();
                let second = parts.next();
                if let (Some(first), Some(second)) = (first, second) {
                    let is_sink = first == "0.0.0.0"
                        || first == "127.0.0.1"
                        || first == "::"
                        || first == "::1"
                        || first.parse::<IpAddr>().is_ok();
                    if is_sink {
                        if let Some(domain) = domain_from_token(second) {
                            parsed.domains.insert(domain);
                        }
                        continue;
                    }
                }
                if let Some(domain) = domain_from_token(first.unwrap_or("")) {
                    parsed.domains.insert(domain);
                }
            }
            ListFormat::Adblock => {
                if let Some(start) = line.find("||") {
                    let rest = &line[start + 2..];
                    let end = rest
                        .find('^')
                        .or_else(|| rest.find('$'))
                        .or_else(|| rest.find('/'))
                        .unwrap_or(rest.len());
                    let candidate = &rest[..end];
                    if let Some(domain) = domain_from_token(candidate) {
                        parsed.domains.insert(domain);
                    }
                } else if let Some(domain) = domain_from_token(line) {
                    parsed.domains.insert(domain);
                }
            }
            ListFormat::Wildcard => {
                let candidate = line
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .trim_start_matches("*.");
                if let Some(domain) = domain_from_token(candidate) {
                    parsed.domains.insert(domain);
                }
            }
            ListFormat::Plain => {
                let candidate = line.split_whitespace().next().unwrap_or("");
                if let Some(ip) = parse_ip_net(candidate) {
                    if seen_ips.insert(ip) {
                        parsed.ips.push(ip);
                    }
                    continue;
                }
                if let Some(domain) = domain_from_token(candidate) {
                    parsed.domains.insert(domain);
                }
            }
        }
    }
    parsed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn parses_hosts_format() {
        let text = "# comment\n0.0.0.0 ads.example.com\n127.0.0.2 tracker.test\n0.0.0.0 foo.bar # inline\n";
        let parsed = parse_list(text, ListFormat::Hosts);
        assert!(parsed.domains.contains("ads.example.com"));
        assert!(parsed.domains.contains("tracker.test"));
        assert!(parsed.domains.contains("foo.bar"));
        assert_eq!(parsed.domains.len(), 3);
    }

    #[test]
    fn parses_adblock_format() {
        let text = "[Adblock Plus]\n! comment\n||ads.example.com^\n||tracker.test^$third-party\n";
        let parsed = parse_list(text, ListFormat::Adblock);
        assert!(parsed.domains.contains("ads.example.com"));
        assert!(parsed.domains.contains("tracker.test"));
    }

    #[test]
    fn parses_wildcard_format() {
        let text = "# OISD\n*.ads.example.com\nplain.test\n";
        let parsed = parse_list(text, ListFormat::Wildcard);
        assert!(parsed.domains.contains("ads.example.com"));
        assert!(parsed.domains.contains("plain.test"));
    }

    #[test]
    fn parses_plain_and_ip_format() {
        let text = "# phishing\nbad.example\n10.0.0.0/8\n2001:db8::1\n";
        let parsed = parse_list(text, ListFormat::Plain);
        assert!(parsed.domains.contains("bad.example"));
        assert_eq!(parsed.ips.len(), 2);
    }

    #[test]
    fn unbreak_allow_sources_lift_list_blocks_but_not_user_rules() {
        let mut block = ParsedList::default();
        block.domains.insert("example.com".to_string());
        block.domains.insert("allowed.example.com".to_string());
        let mut allow = ParsedList::default();
        allow.domains.insert("allowed.example.com".to_string());
        let rules = Rules {
            custom_block: vec!["blocked.example.com".to_string()],
            ..Rules::default()
        };
        let index = build_index(
            &[
                (true, Action::Block, block),
                (true, Action::Allow, allow),
            ],
            &rules,
        );
        assert_eq!(
            index.domain_match("allowed.example.com"),
            Some(DomainMatch::Allow)
        );
        assert_eq!(
            index.domain_match("example.com"),
            Some(DomainMatch::Block)
        );
        assert_eq!(
            index.domain_match("blocked.example.com"),
            Some(DomainMatch::Block)
        );
    }

    #[test]
    fn suffix_matching_and_allow_precedence() {
        let mut index = DomainIndex::default();
        index.block.insert("example.com".to_string());
        index.allow.insert("safe.example.com".to_string());
        assert_eq!(
            index.domain_match("ads.example.com"),
            Some(DomainMatch::Block)
        );
        assert_eq!(
            index.domain_match("safe.example.com"),
            Some(DomainMatch::Allow)
        );
        assert_eq!(index.domain_match("unrelated.test"), None);
    }

    #[test]
    fn cidr_matching() {
        let net = parse_ip_net("192.168.1.0/24").unwrap();
        assert!(net.contains("192.168.1.42".parse().unwrap()));
        assert!(!net.contains("192.168.2.1".parse().unwrap()));
        let v6 = parse_ip_net("2001:db8::/32").unwrap();
        assert!(v6.contains("2001:db8::5".parse().unwrap()));
        assert!(!v6.contains("2001:db9::5".parse().unwrap()));
    }

    #[test]
    fn invalid_domains_are_rejected() {
        assert!(normalize_domain("example.com.").is_some());
        assert!(normalize_domain("*").is_none());
        assert!(normalize_domain("bad domain").is_none());
        assert!(normalize_domain("http://example.com").is_none());
    }

    #[test]
    fn ipv4_and_ipv6_parse() {
        let v4 = Ipv4Addr::new(127, 0, 0, 1);
        let v6 = Ipv6Addr::LOCALHOST;
        assert!(IpAddr::V4(v4).is_ipv4());
        assert!(IpAddr::V6(v6).is_ipv6());
    }

    #[test]
    fn duplicate_lines_and_cidrs_are_deduplicated() {
        let text = "bad.example\nbad.example\n10.0.0.0/8\n10.0.0.0/8\n2001:db8::/32\n";
        let parsed = parse_list(text, ListFormat::Plain);
        assert_eq!(parsed.domains.len(), 1);
        assert_eq!(parsed.ips.len(), 2);
    }

    #[test]
    fn cross_list_ip_duplicates_are_removed_from_the_index() {
        let mut first = ParsedList::default();
        first.ips.push(parse_ip_net("10.0.0.0/8").unwrap());
        let mut second = ParsedList::default();
        second.ips.push(parse_ip_net("10.0.0.0/8").unwrap());
        let rules = Rules {
            ip_block: vec!["10.0.0.0/8".to_string()],
            ..Rules::default()
        };
        let index = build_index(
            &[
                (true, Action::Block, first),
                (true, Action::Block, second),
            ],
            &rules,
        );
        assert_eq!(index.ip_block.len(), 1);
    }

    #[test]
    fn single_host_ip_only_matches_itself() {
        let mut parsed = ParsedList::default();
        parsed.ips.push(parse_ip_net("10.0.0.1").unwrap());
        let index = build_index(&[(true, Action::Block, parsed)], &Rules::default());
        assert_eq!(
            index.ip_match("10.0.0.1".parse().unwrap()),
            Some(DomainMatch::Block)
        );
        assert_eq!(index.ip_match("10.0.0.2".parse().unwrap()), None);
    }

    #[test]
    fn zero_prefix_matches_any_address_of_the_same_family() {
        let v4 = parse_ip_net("0.0.0.0/0").unwrap();
        assert!(v4.contains("203.0.113.9".parse().unwrap()));
        assert!(!v4.contains("2001:db8::1".parse().unwrap()));
        let v6 = parse_ip_net("::/0").unwrap();
        assert!(v6.contains("2001:db8::1".parse().unwrap()));
        assert!(!v6.contains("192.0.2.1".parse().unwrap()));
    }
}
