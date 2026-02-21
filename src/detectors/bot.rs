//! # detectors/bot.rs – Bot and Scanner Fingerprint Detector
//!
//! Identifies automated scanners, vulnerability assessment tools, and
//! headless browsers by matching the `User-Agent` header against a
//! curated list of tool signatures.
//!
//! ## Strategy
//! User-Agent matching is the fastest possible check (header-phase, no body
//! needed) so it acts as an early-exit gate that can block scanners before
//! they burn body-buffering budget. This runs in `on_http_request_headers`.
//!
//! ## Limitations
//! Sophisticated bots spoof legitimate UA strings. Bot detection is one
//! layer of a defence-in-depth strategy; rate limiting and behavioural
//! analysis (v0.2) will complement it.

use crate::types::{sanitise_evidence, AttackType, ThreatReport};
use regex_lite::Regex;

/// Bot/scanner User-Agent signatures. Index positions are stable for SIEM.
pub const BOT_UA_PATTERNS: &[&str] = &[
    // [0-11] Known offensive security / scanning tools
    r"(?i)sqlmap",
    r"(?i)nikto",
    r"(?i)nmap",
    r"(?i)masscan",
    r"(?i)zgrab",
    r"(?i)nuclei",
    r"(?i)hydra",
    r"(?i)burpsuite",
    r"(?i)dirbuster",
    r"(?i)gobuster",
    r"(?i)wfuzz",
    r"(?i)acunetix",
    // [12-14] Generic automation signals (configurable block via WafConfig)
    r"(?i)python-requests/\d", // very common in automated scripts
    r"(?i)go-http-client/\d",  // Go's default http.Client UA
    r"(?i)libwww-perl",        // Perl LWP; rarely legitimate in modern systems
];

/// Compile the bot UA pattern array into a `RegexSet`.
pub fn build_bot_set() -> Result<Vec<Regex>, String> {
    BOT_UA_PATTERNS
        .iter()
        .enumerate()
        .map(|(i, &p)| Regex::new(p).map_err(|e| format!("Bot UA Regex [{i}] build failed: {e}")))
        .collect()
}

/// Check `user_agent` for known scanner / automation tool signatures.
///
/// Also checks for a completely missing User-Agent, which is itself
/// a strong bot signal (controlled by `block_on_missing_ua` in config).
///
/// Returns `None` if the UA looks legitimate, or `Some(ThreatReport)`
/// with a confidence of `0.85` (slightly lower than SQLi/XSS because
/// legitimate tools can match these patterns in some environments).
pub fn detect(user_agent: &str, set: &[Regex]) -> Option<ThreatReport> {
    if user_agent.is_empty() {
        // Absence of User-Agent: not conclusive alone but suspicious.
        // Caller (http_context) decides whether to block based on config.
        return Some(ThreatReport::new(
            AttackType::Bot,
            0.50, // low confidence – many SDKs omit UA
            "<missing user-agent>".to_string(),
            None,
        ));
    }

    let mut first_rule = None;
    for (i, re) in set.iter().enumerate() {
        if re.is_match(user_agent) {
            first_rule = Some(i);
            break;
        }
    }
    let first_rule = first_rule?;

    let evidence = sanitise_evidence(user_agent.as_bytes(), 150);

    Some(ThreatReport::new(
        AttackType::Bot,
        0.85,
        evidence,
        Some(first_rule),
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn set() -> Vec<Regex> {
        build_bot_set().expect("test set build failed")
    }

    #[test]
    fn detects_sqlmap() {
        let ua = "sqlmap/1.7.8#stable (https://sqlmap.org)";
        let rep = detect(ua, &set());
        assert!(rep.is_some());
        assert_eq!(rep.unwrap().attack_type, AttackType::Bot);
    }

    #[test]
    fn detects_nikto() {
        assert!(detect("Nikto/2.1.6", &set()).is_some());
    }

    #[test]
    fn detects_python_requests() {
        assert!(detect("python-requests/2.31.0", &set()).is_some());
    }

    #[test]
    fn missing_ua_returns_low_confidence_report() {
        let rep = detect("", &set()).expect("should return a report for missing UA");
        assert!((rep.confidence - 0.50).abs() < f32::EPSILON);
        assert!(rep.rule_id.is_none());
    }

    #[test]
    fn no_false_positive_on_chrome() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
                  AppleWebKit/537.36 (KHTML, like Gecko) \
                  Chrome/120.0.0.0 Safari/537.36";
        assert!(detect(ua, &set()).is_none(), "false positive on Chrome UA");
    }

    #[test]
    fn no_false_positive_on_firefox() {
        let ua = "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0";
        assert!(detect(ua, &set()).is_none(), "false positive on Firefox UA");
    }

    #[test]
    fn confidence_for_known_tool_is_high() {
        let rep = detect("sqlmap/1.7", &set()).expect("should match");
        assert!(rep.confidence >= 0.8);
    }
}
