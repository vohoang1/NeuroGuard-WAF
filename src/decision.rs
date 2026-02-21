//! # decision.rs – Risk Aggregation and Enforcement Decision Engine
//!
//! After all detection phases have run, this module collects their outputs
//! (a list of [`ThreatReport`]s and an AI risk score) and reduces them to a
//! single [`Decision`] that the HTTP context enforces.
//!
//! ## Decision logic (v1)
//!
//! ```text
//! ┌───────────────────────────────────────┐
//! │ Any report.confidence > threshold?    │──YES──► Block
//! └───────────────────────────────────────┘
//!             │ NO
//!             ▼
//! ┌───────────────────────────────────────┐
//! │ ai_score > ai_threshold?              │──YES──► Block
//! └───────────────────────────────────────┘
//!             │ NO
//!             ▼
//! ┌───────────────────────────────────────┐
//! │ Any report exists (lower confidence)? │──YES──► Challenge
//! └───────────────────────────────────────┘
//!             │ NO
//!             ▼
//!           Allow
//! ```
//!
//! Thresholds are loaded from [`crate::types::WafConfig`] so operators can
//! tune false-positive vs false-negative trade-offs without recompiling.

use crate::types::{Decision, ThreatReport};

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate all threat reports and the AI risk score into a single decision.
///
/// ## Parameters
/// * `reports`            – All findings accumulated across header, body, and
///                          trailer phases for this request.
/// * `ai_score`           – Semantic risk score (0.0–1.0) from
///                          [`crate::semantic::scorer::calculate_risk_score`].
/// * `confidence_threshold` – Per-report confidence level that triggers a block.
///                            Loaded from `WafConfig.confidence_threshold`.
/// * `ai_threshold`       – AI score level that triggers a block.
///                          Loaded from `WafConfig.ai_score_threshold`.
///
/// ## Returns
/// A [`Decision`] variant that the HTTP context translates into an Envoy action.
pub fn evaluate(
    reports: &[ThreatReport],
    ai_score: f32,
    confidence_threshold: f32,
    ai_threshold: f32,
) -> Decision {
    // ── Stage 1: High-confidence signature match → immediate block ────────
    // Signature rules are deterministic; a confidence above the threshold
    // (typically 0.9) means we've matched a known-bad pattern with very
    // low false-positive probability.
    let high_confidence_hit = reports.iter().any(|r| r.confidence >= confidence_threshold);

    if high_confidence_hit {
        log::info!(
            target: "neuroguard_waf",
            "decision=BLOCK reason=high_confidence_signature"
        );
        return Decision::Block;
    }

    // ── Stage 2: AI anomaly detection → block on high risk score ─────────
    // The AI model (currently mocked; ONNX integration in v0.2) assigns a
    // continuous risk score. We block above `ai_threshold` (default 0.8).
    if ai_score >= ai_threshold {
        log::info!(
            target: "neuroguard_waf",
            "decision=BLOCK reason=ai_score score={:.4}",
            ai_score
        );
        return Decision::Block;
    }

    // ── Stage 3: Low-confidence findings → challenge ──────────────────────
    // Something was suspicious (e.g., a bot UA or a borderline pattern) but
    // not conclusively malicious. We issue a challenge rather than blocking
    // legitimate traffic. In v0.1 this is logged; the redirect is v0.2.
    if !reports.is_empty() {
        log::debug!(
            target: "neuroguard_waf",
            "decision=CHALLENGE reason=low_confidence_findings count={}",
            reports.len()
        );
        return Decision::Challenge;
    }

    // ── Stage 4: No signals → allow ──────────────────────────────────────
    log::debug!(target: "neuroguard_waf", "decision=ALLOW");
    Decision::Allow
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AttackType, ThreatReport};

    const CT: f32 = 0.9; // confidence threshold
    const AT: f32 = 0.8; // ai threshold

    fn sqli_report(confidence: f32) -> ThreatReport {
        ThreatReport::new(
            AttackType::SqlInjection,
            confidence,
            "UNION SELECT",
            Some(0),
        )
    }

    fn xss_report(confidence: f32) -> ThreatReport {
        ThreatReport::new(AttackType::Xss, confidence, "<script>", Some(1))
    }

    #[test]
    fn high_confidence_sqli_blocks() {
        let reports = vec![sqli_report(0.95)];
        assert_eq!(evaluate(&reports, 0.0, CT, AT), Decision::Block);
    }

    #[test]
    fn high_confidence_xss_blocks() {
        let reports = vec![xss_report(0.92)];
        assert_eq!(evaluate(&reports, 0.0, CT, AT), Decision::Block);
    }

    #[test]
    fn high_ai_score_blocks_even_without_signature() {
        assert_eq!(evaluate(&[], 0.85, CT, AT), Decision::Block);
    }

    #[test]
    fn ai_score_exactly_at_threshold_blocks() {
        // Threshold is inclusive (>=).
        assert_eq!(evaluate(&[], 0.8, CT, AT), Decision::Block);
    }

    #[test]
    fn low_confidence_finding_challenges() {
        let reports = vec![sqli_report(0.6)];
        assert_eq!(evaluate(&reports, 0.0, CT, AT), Decision::Challenge);
    }

    #[test]
    fn no_signals_allows() {
        assert_eq!(evaluate(&[], 0.0, CT, AT), Decision::Allow);
    }

    #[test]
    fn ai_score_below_threshold_with_no_reports_allows() {
        assert_eq!(evaluate(&[], 0.79, CT, AT), Decision::Allow);
    }

    #[test]
    fn confidence_exactly_at_threshold_blocks() {
        // Threshold is inclusive (>=).
        let reports = vec![sqli_report(0.9)];
        assert_eq!(evaluate(&reports, 0.0, CT, AT), Decision::Block);
    }

    #[test]
    fn multiple_low_confidence_reports_challenge_not_block() {
        // Volume of low-confidence hits should NOT escalate to Block in v1.
        // That logic belongs in v2 with a weighted-sum model.
        let reports = vec![sqli_report(0.5), xss_report(0.4)];
        assert_eq!(evaluate(&reports, 0.0, CT, AT), Decision::Challenge);
    }
}
