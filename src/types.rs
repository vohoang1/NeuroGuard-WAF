//! # types.rs – Shared domain types for NeuroGuard WAF
//!
//! All structs and enums used across detectors, the decision engine,
//! and the audit logger are centralised here to prevent circular
//! dependencies and ensure a single source of truth.

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Attack classification
// ─────────────────────────────────────────────────────────────────────────────

/// Canonical attack categories recognised by NeuroGuard.
///
/// Adding a new category here is the first step to integrating a new
/// detector module – the type system will guide the remaining changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackType {
    /// SQL injection (OWASP A03:2021 – Injection)
    SqlInjection,
    /// Cross-site scripting – reflected, stored, or DOM (OWASP A07:2021)
    Xss,
    /// Automated scanner / bot fingerprint detected
    Bot,
    /// Catch-all for anomalies that don't fit a specific category.
    /// Typically raised by the AI scoring stage when no signature matched.
    Unknown,
}

impl AttackType {
    /// Returns a short, stable string identifier suitable for SIEM field values.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SqlInjection => "SQL_INJECTION",
            Self::Xss         => "XSS",
            Self::Bot         => "BOT_SCANNER",
            Self::Unknown     => "UNKNOWN",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Threat report – the unit of output from every detector
// ─────────────────────────────────────────────────────────────────────────────

/// A finding produced by a single detection stage.
///
/// Each detector function returns `Option<ThreatReport>`: `None` means
/// no threat found; `Some(report)` carries the evidence that triggered it.
///
/// Multiple reports can accumulate across the header, body, and trailer
/// phases before the final decision is made.
#[derive(Debug, Clone, Serialize)]
pub struct ThreatReport {
    /// Category of the detected attack.
    pub attack_type: AttackType,

    /// Confidence score in [0.0, 1.0].
    ///
    /// Signature-based detectors typically emit 0.95 (high confidence)
    /// because the pattern is deterministic. Heuristic detectors may
    /// emit lower values (e.g. 0.6) that combine with the AI score
    /// in the decision engine.
    pub confidence: f32,

    /// Short, sanitised excerpt of the offending payload included for
    /// audit trail purposes. MUST NOT contain full user-controlled input
    /// to prevent log injection. Truncated to 200 bytes by detectors.
    pub evidence: String,

    /// Zero-based index of the regex rule that fired, used to cross-
    /// reference with the OWASP rule catalogue in SIEM dashboards.
    pub rule_id: Option<usize>,
}

impl ThreatReport {
    /// Convenience constructor.
    pub fn new(
        attack_type: AttackType,
        confidence: f32,
        evidence: impl Into<String>,
        rule_id: Option<usize>,
    ) -> Self {
        Self {
            attack_type,
            confidence: confidence.clamp(0.0, 1.0),
            evidence: evidence.into(),
            rule_id,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Decision – the final enforcement action
// ─────────────────────────────────────────────────────────────────────────────

/// The enforcement action returned by [`crate::decision::evaluate`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Decision {
    /// Request is clean – pass it upstream to the backend service.
    Allow,

    /// Request is malicious – return a 403 to the client immediately.
    /// The upstream never sees this request.
    Block,

    /// Request is suspicious but not conclusively malicious.
    /// In future this will redirect to a CAPTCHA / JS challenge endpoint.
    /// Currently treated as `Allow` with a SIEM warning log.
    Challenge,
}

// ─────────────────────────────────────────────────────────────────────────────
// Plugin configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Deserialised WAF configuration passed via Envoy's `PluginConfig.configuration`
/// field (base64-decoded JSON, delivered in `on_vm_start`).
///
/// Every field has a `#[serde(default)]` so partial configs are accepted
/// gracefully – missing fields fall back to safe defaults.
#[derive(Debug, Clone, Deserialize)]
pub struct WafConfig {
    /// Enable SQL injection detection.
    #[serde(default = "default_true")]
    pub enable_sqli: bool,

    /// Enable XSS detection.
    #[serde(default = "default_true")]
    pub enable_xss: bool,

    /// Enable bot / scanner User-Agent fingerprinting.
    #[serde(default = "default_true")]
    pub enable_bot_detection: bool,

    /// Confidence threshold above which a single report triggers a block.
    /// Default: 0.9 (must be very high confidence for signature rules).
    #[serde(default = "default_confidence_threshold")]
    pub confidence_threshold: f32,

    /// AI risk score (0.0–1.0) above which the request is blocked.
    /// Default: 0.8.
    #[serde(default = "default_ai_threshold")]
    pub ai_score_threshold: f32,

    /// Maximum request body bytes to buffer before blocking.
    /// Default: 1 MB. Hard-capped at 1 MB in root_context.rs.
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,

    /// Block requests with no User-Agent header.
    #[serde(default)]
    pub block_on_missing_ua: bool,
}

fn default_true()                -> bool  { true }
fn default_confidence_threshold() -> f32  { 0.9 }
fn default_ai_threshold()         -> f32  { 0.8 }
fn default_max_body_bytes()       -> usize { 1 * 1024 * 1024 }

impl Default for WafConfig {
    fn default() -> Self {
        Self {
            enable_sqli:              true,
            enable_xss:               true,
            enable_bot_detection:     true,
            confidence_threshold:     0.9,
            ai_score_threshold:       0.8,
            max_body_bytes:           1 * 1024 * 1024,
            block_on_missing_ua:      false,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility
// ─────────────────────────────────────────────────────────────────────────────

/// Sanitise a raw byte slice into a printable string safe for JSON log output.
///
/// Non-ASCII and non-printable bytes are replaced with `.` to prevent:
///   1. Log injection via control characters (ANSI escape codes, newlines).
///   2. UTF-8 decode panics.
///   3. Excessively long log lines (truncated to `max_bytes`).
pub fn sanitise_evidence(raw: &[u8], max_bytes: usize) -> String {
    raw.iter()
        .take(max_bytes)
        .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attack_type_as_str_stable() {
        assert_eq!(AttackType::SqlInjection.as_str(), "SQL_INJECTION");
        assert_eq!(AttackType::Xss.as_str(), "XSS");
        assert_eq!(AttackType::Bot.as_str(), "BOT_SCANNER");
        assert_eq!(AttackType::Unknown.as_str(), "UNKNOWN");
    }

    #[test]
    fn threat_report_confidence_clamped() {
        let r = ThreatReport::new(AttackType::SqlInjection, 1.5, "test", None);
        assert!((r.confidence - 1.0).abs() < f32::EPSILON, "must clamp to 1.0");

        let r2 = ThreatReport::new(AttackType::Xss, -0.3, "test", None);
        assert!((r2.confidence - 0.0).abs() < f32::EPSILON, "must clamp to 0.0");
    }

    #[test]
    fn sanitise_replaces_control_chars() {
        let raw = b"\x00\x1b[31mALERT\x00";
        let s   = sanitise_evidence(raw, 100);
        assert!(!s.contains('\x00'));
        assert!(!s.contains('\x1b'));
        assert!(s.contains("ALERT"));
    }

    #[test]
    fn sanitise_truncates() {
        let raw    = b"ABCDEFGHIJ";
        let result = sanitise_evidence(raw, 4);
        assert_eq!(result, "ABCD");
    }

    #[test]
    fn waf_config_defaults() {
        let cfg = WafConfig::default();
        assert!(cfg.enable_sqli);
        assert!(cfg.enable_xss);
        assert!((cfg.confidence_threshold - 0.9).abs() < f32::EPSILON);
        assert_eq!(cfg.max_body_bytes, 1024 * 1024);
    }

    #[test]
    fn waf_config_partial_json() {
        let json = r#"{"enable_xss": false}"#;
        let cfg: WafConfig = serde_json::from_str(json).expect("parse failed");
        // Non-provided fields fall back to defaults.
        assert!(cfg.enable_sqli);
        assert!(!cfg.enable_xss);
        assert!((cfg.confidence_threshold - 0.9).abs() < f32::EPSILON);
    }
}