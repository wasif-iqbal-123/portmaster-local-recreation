use crate::config::{Action, Scope};
use crate::filter::DomainIndex;
use crate::monitor::ProcessInfo;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct AppRule {
    pub id: String,
    pub app_match: String,
    pub action: Action,
    pub scope: Scope,
}

impl Default for AppRule {
    fn default() -> Self {
        Self {
            id: String::new(),
            app_match: String::new(),
            action: Action::Allow,
            scope: Scope::All,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Rules {
    pub custom_block: Vec<String>,
    pub custom_allow: Vec<String>,
    pub ip_block: Vec<String>,
    pub ip_allow: Vec<String>,
    pub app_rules: Vec<AppRule>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Decision {
    pub action: Action,
    pub reason: String,
    pub app: Option<ProcessInfo>,
}

pub fn is_localhost_domain(domain: &str) -> bool {
    domain == "localhost" || domain.ends_with(".localhost")
}

pub fn is_lan_domain(domain: &str) -> bool {
    const LAN_SUFFIXES: [&str; 6] = [
        ".local",
        ".lan",
        ".home.arpa",
        ".internal",
        ".intranet",
        ".localdomain",
    ];
    is_localhost_domain(domain)
        || LAN_SUFFIXES.iter().any(|suffix| domain.ends_with(suffix))
}

fn scope_applies(scope: Scope, domain: &str) -> bool {
    match scope {
        Scope::All => true,
        Scope::Internet => !is_lan_domain(domain),
        Scope::Lan => is_lan_domain(domain),
        Scope::Localhost => is_localhost_domain(domain),
    }
}

fn normalized(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

pub fn app_matches(app_match: &str, app: &ProcessInfo) -> bool {
    let needle = normalized(app_match);
    if needle.is_empty() {
        return false;
    }
    let name = normalized(&app.name);
    let path = normalized(&app.path);
    let stem = name.strip_suffix(".exe").unwrap_or(&name);
    if needle == name || needle == stem || needle == path {
        return true;
    }
    path.ends_with(&needle)
}

/// Returns the first applicable per-app rule. Rules are matched by executable
/// name, full path, or path suffix, case-insensitively.
pub fn app_rule_for<'a>(
    rules: &'a Rules,
    app: Option<&ProcessInfo>,
    domain: &str,
) -> Option<&'a AppRule> {
    let app = app?;
    rules
        .app_rules
        .iter()
        .find(|rule| app_matches(&rule.app_match, app) && scope_applies(rule.scope, domain))
}

pub fn evaluate(
    index: &DomainIndex,
    rules: &Rules,
    default_action: Action,
    app: Option<&ProcessInfo>,
    domain: &str,
) -> Decision {
    if let Some(rule) = app_rule_for(rules, app, domain) {
        return Decision {
            action: rule.action,
            reason: format!("per-app {:?} rule", rule.action),
            app: app.cloned(),
        };
    }

    let domain_match = index.domain_match(domain);
    let (final_action, reason) = match default_action {
        Action::Allow => match domain_match {
            Some(crate::filter::DomainMatch::Allow) => (
                Action::Allow,
                "allow-listed domain".to_string(),
            ),
            Some(crate::filter::DomainMatch::Block) => (
                Action::Block,
                "domain is on a block list".to_string(),
            ),
            None => (Action::Allow, "default allow".to_string()),
        },
        Action::Block => match domain_match {
            Some(crate::filter::DomainMatch::Allow) => (
                Action::Allow,
                "allow-listed domain overrides default block".to_string(),
            ),
            Some(crate::filter::DomainMatch::Block) => (
                Action::Block,
                "domain is on a block list".to_string(),
            ),
            None => (Action::Block, "default block".to_string()),
        },
    };

    Decision {
        action: final_action,
        reason,
        app: app.cloned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::DomainIndex;
    use crate::monitor::ProcessInfo;

    fn process(name: &str, path: &str) -> ProcessInfo {
        ProcessInfo {
            pid: 42,
            name: name.to_string(),
            path: path.to_string(),
        }
    }

    #[test]
    fn app_matching_is_case_insensitive_and_suffix_based() {
        let app = process("chrome.exe", "C:\\Program Files\\Google\\Chrome\\chrome.exe");
        assert!(app_matches("chrome.exe", &app));
        assert!(app_matches("chrome", &app));
        assert!(app_matches("C:\\Program Files\\Google\\Chrome\\chrome.exe", &app));
        assert!(!app_matches("firefox.exe", &app));
    }

    #[test]
    fn allow_list_overrides_block_list() {
        let mut index = DomainIndex::default();
        index.block.insert("example.com".to_string());
        index.allow.insert("safe.example.com".to_string());
        let rules = Rules::default();
        let decision = evaluate(&index, &rules, Action::Allow, None, "safe.example.com");
        assert_eq!(decision.action, Action::Allow);
        let decision = evaluate(&index, &rules, Action::Allow, None, "ads.example.com");
        assert_eq!(decision.action, Action::Block);
    }

    #[test]
    fn per_app_allow_bypasses_global_block_list() {
        let mut index = DomainIndex::default();
        index.block.insert("example.com".to_string());
        let rules = Rules {
            app_rules: vec![AppRule {
                id: "r1".to_string(),
                app_match: "chrome.exe".to_string(),
                action: Action::Allow,
                scope: Scope::Internet,
            }],
            ..Rules::default()
        };
        let app = process("chrome.exe", "C:\\Chrome\\chrome.exe");
        let decision = evaluate(&index, &rules, Action::Allow, Some(&app), "ads.example.com");
        assert_eq!(decision.action, Action::Allow);
    }

    #[test]
    fn internet_scope_does_not_apply_to_lan_domains() {
        let rules = Rules {
            app_rules: vec![AppRule {
                id: "r1".to_string(),
                app_match: "nas.exe".to_string(),
                action: Action::Block,
                scope: Scope::Internet,
            }],
            ..Rules::default()
        };
        let app = process("nas.exe", "C:\\nas.exe");
        let index = DomainIndex::default();
        let decision = evaluate(&index, &rules, Action::Allow, Some(&app), "disk.local");
        assert_eq!(decision.action, Action::Allow);
        assert!(app_rule_for(&rules, Some(&app), "disk.local").is_none());
    }
}
