//! # detectors/xss.rs – Cross-Site Scripting Detector
//!
//! Signature-based XSS detection using pre-compiled `regex-lite` patterns.
//!
//! ## Coverage (OWASP A07:2021 – XSS)
//! - Script tag injection (reflected, stored)
//! - JavaScript URI scheme (href, src, action)
//! - Inline event handler injection (onerror, onload, onmouseover, …)
//! - CSS expression() injection (legacy IE)
//! - Data URI with script content
//! - VBScript URI (legacy IE)
//! - HTML entity encoding bypass (&#x3C; etc.)
//! - Client-side template injection ({{ }})

use crate::types::{sanitise_evidence, AttackType, ThreatReport};
use regex_lite::Regex;

/// All XSS detection patterns. Index positions are stable for SIEM rule_id.
pub const XSS_PATTERNS: &[&str] = &[
    // [0] Opening script tag – with or without attributes
    r"(?i)<\s*script[\s>/]",
    // [1] Closing script tag
    r"(?i)<\s*/\s*script\s*>",
    // [2] javascript: URI scheme – optional whitespace for evasion
    r"(?i)javascript\s*:",
    // [3] Inline event handlers: on{event}= covering all DOM events
    r"(?i)\bon\w{1,20}\s*=",
    // [4] CSS expression() – legacy IE XSS vector
    r"(?i)expression\s*\(",
    // [5] data: URI with HTML content
    r"(?i)data\s*:\s*text/html",
    // [6] data: URI with JS content
    r"(?i)data\s*:\s*(?:application|text)/(?:javascript|ecmascript)",
    // [7] VBScript URI – legacy IE
    r"(?i)vbscript\s*:",
    // [8] HTML entity encoding bypass (decimal or hex)
    r"&#x?[0-9a-fA-F]{2,4};",
    // [9] Client-side template injection (Angular, Vue, Handlebars, Jinja2)
    r"\{\{[\s\S]{1,200}\}\}",
    // [10] src/href with encoded/dangerous scheme
    r#"(?i)(?:src|href|action)\s*=\s*["']?\s*(?:javascript|data|vbscript)"#,
];

/// Compile the XSS pattern array into a `RegexSet`.
pub fn build_xss_set() -> Result<Vec<Regex>, String> {
    XSS_PATTERNS
        .iter()
        .enumerate()
        .map(|(i, &p)| Regex::new(p).map_err(|e| format!("XSS Regex [{i}] build failed: {e}")))
        .collect()
}

/// Scan `input` for XSS patterns using the pre-compiled `set`.
///
/// Returns `None` if no patterns match, or `Some(ThreatReport)` with
/// a confidence of `0.93` (high – these are distinctive patterns with
/// low false-positive rates on typical API payloads).
pub fn detect(input: &str, set: &[Regex]) -> Option<ThreatReport> {
    let mut first_rule = None;
    for (i, re) in set.iter().enumerate() {
        if re.is_match(input) {
            first_rule = Some(i);
            break;
        }
    }
    let first_rule = first_rule?;

    let evidence = sanitise_evidence(input.as_bytes(), 200);

    Some(ThreatReport::new(
        AttackType::Xss,
        0.93,
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
        build_xss_set().expect("test set build failed")
    }

    #[test]
    fn detects_script_tag() {
        for p in &[
            "<script>alert(1)</script>",
            "<SCRIPT SRC='evil.com'>",
            "</script>",
        ] {
            assert!(detect(p, &set()).is_some(), "expected XSS match for: {}", p);
        }
    }

    #[test]
    fn detects_event_handler() {
        for p in &[
            r#"<img src=x onerror="alert(1)">"#,
            "<body onload=alert(1)>",
            "<a onmouseover=alert(1)>",
        ] {
            assert!(detect(p, &set()).is_some(), "expected XSS match for: {}", p);
        }
    }

    #[test]
    fn detects_javascript_uri() {
        for p in &[
            r#"<a href="javascript:alert(1)">"#,
            "javascript:void(0)",
            "javascript  :alert(1)",
        ] {
            assert!(detect(p, &set()).is_some(), "expected XSS match for: {}", p);
        }
    }

    #[test]
    fn detects_template_injection() {
        assert!(detect("{{constructor.constructor('alert(1)')()}}", &set()).is_some());
    }

    #[test]
    fn detects_data_uri() {
        assert!(detect(
            r#"<iframe src="data:text/html,<script>alert(1)</script>">"#,
            &set()
        )
        .is_some());
    }

    #[test]
    fn no_false_positive_on_clean_html() {
        // A plain anchor tag with a normal href should NOT match.
        let clean = r#"<a href="https://example.com">click</a>"#;
        assert!(
            detect(clean, &set()).is_none(),
            "false positive on clean HTML"
        );
    }

    #[test]
    fn confidence_value_correct() {
        let rep = detect("<script>alert(1)</script>", &set()).expect("should match");
        assert!((rep.confidence - 0.93).abs() < f32::EPSILON);
    }
}
