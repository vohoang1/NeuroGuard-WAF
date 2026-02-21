//! # http_context.rs – Per-Request WAF Filter Logic
//!
//! `WafHttpContext` is instantiated by [`crate::root_context::WafRootContext`]
//! for every HTTP request. It orchestrates the three-phase detection pipeline:
//!
//! ```text
//! on_http_request_headers  → extract metadata, bot detection, path scanning
//!          │
//!          ▼
//! on_http_request_body     → buffer body (max 1MB), SQLi + XSS scanning
//!          │
//!          ▼
//! on_http_request_trailers → finalise decision (also handles body-less requests)
//!          │
//!          ├── Decision::Block     → send_http_response(403) + audit log
//!          └── Decision::Allow/Challenge → Action::Continue
//! ```
//!
//! ## Memory model
//! `body_buffer` is the only heap allocation per request. It is bounded by
//! `config.max_body_bytes` (≤ 1 MB). The struct is dropped by the SDK
//! after the trailer phase or after a block – no manual cleanup needed.

use crate::audit_log;
use crate::decision;
use crate::detectors::{bot, sqli, xss, DetectorSets};
use crate::semantic::scorer;
use crate::types::{Decision, ThreatReport, WafConfig};
use proxy_wasm::traits::{Context, HttpContext};
use proxy_wasm::types::Action;
use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const BLOCK_STATUS: u32 = 403;
const BLOCK_BODY: &str =
    r#"{"error":"Forbidden","message":"Blocked by NeuroGuard WAF","code":403}"#;

// ─────────────────────────────────────────────────────────────────────────────
// Per-request state
// ─────────────────────────────────────────────────────────────────────────────

pub struct WafHttpContext {
    config: WafConfig,

    /// Pre-compiled regex sets cloned from root context (cheap Arc clone).
    /// `None` only when root context failed to build patterns at startup.
    detectors: Option<DetectorSets>,

    // ── Request metadata (populated in header phase) ──────────────────────
    pub source_ip: String,
    pub method: String,
    pub path: String,
    pub user_agent: String,
    pub tenant_id: String,

    // ── Accumulated findings across all phases ────────────────────────────
    /// Every detector appends to this Vec. The decision engine reads it
    /// after the final phase. Capacity pre-allocated to 4 to avoid
    /// reallocations in the common case (most requests have 0–2 findings).
    findings: Vec<ThreatReport>,

    // ── Body buffering ────────────────────────────────────────────────────
    /// Concatenated request body chunks. Bounded by config.max_body_bytes.
    body_buffer: Vec<u8>,

    // ── State flags ───────────────────────────────────────────────────────
    /// Set to true once a block has been issued so subsequent phase hooks
    /// are skipped (body delivery continues even after a header-phase block
    /// in some Envoy configurations).
    already_blocked: bool,
    dispatched_ai: bool,
    ai_score: Option<f32>,

    /// Cached global blocklist
    blocklist: Rc<RefCell<HashSet<String>>>,
}

impl WafHttpContext {
    pub fn new(
        config: WafConfig,
        detectors: Option<DetectorSets>,
        blocklist: Rc<RefCell<HashSet<String>>>,
    ) -> Self {
        Self {
            config,
            detectors,
            blocklist,
            source_ip: String::new(),
            method: String::new(),
            path: String::new(),
            user_agent: String::new(),
            tenant_id: String::new(),
            findings: Vec::with_capacity(4),
            body_buffer: Vec::new(),
            already_blocked: false,
            dispatched_ai: false,
            ai_score: None,
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // Internal helpers
    // ──────────────────────────────────────────────────────────────────────

    /// Extract the client's originating IP from x-forwarded-for.
    ///
    /// Takes only the leftmost (first) value to prevent IP spoofing via
    /// header stuffing (an attacker appending their own IP to the XFF chain).
    fn extract_source_ip(&self) -> String {
        self.get_http_request_header("x-forwarded-for")
            .and_then(|xff| xff.split(',').next().map(|s| s.trim().to_string()))
            .unwrap_or_else(|| "unknown".to_string())
    }

    /// Enforce a block: send 403 response and emit audit log.
    ///
    /// Called at most once per request (guarded by `already_blocked`).
    /// Must be called BEFORE returning `Action::Pause` from a hook.
    fn enforce_block(&mut self, ai_score: f32) {
        // Use the first (highest-priority) finding as the primary log entry.
        // All findings are available in `self.findings` if needed for v0.2
        // bulk logging.
        let primary = match self.findings.first() {
            Some(r) => r.clone(),
            None => {
                // If AI blocked but no findings exist
                use crate::types::{AttackType, ThreatReport};
                ThreatReport::new(
                    AttackType::Unknown,
                    ai_score,
                    "Semantic Anomaly (AI Block)".to_string(),
                    None,
                )
            }
        };

        // Emit the audit log BEFORE send_http_response to guarantee the event
        // is captured even if the response call fails.
        audit_log::log_event(
            &primary,
            &self.method,
            &self.path,
            &self.source_ip,
            &self.user_agent,
            ai_score,
            &Decision::Block,
            &self.tenant_id,
        );

        self.send_http_response(
            BLOCK_STATUS,
            vec![
                ("content-type", "application/json"),
                ("x-neuroguard-action", "block"),
                ("x-neuroguard-rule", primary.attack_type.as_str()),
                // Never reflect the payload snippet back to the client.
                // Doing so could help an attacker refine their bypass.
            ],
            Some(BLOCK_BODY.as_bytes()),
        );

        self.already_blocked = true;
    }

    /// Run the full decision pipeline and enforce the result.
    ///
    /// Called at the end of body phase and again in trailer phase
    /// (idempotent because `already_blocked` guards re-entry).
    fn run_decision_pipeline(&mut self) -> Action {
        if self.already_blocked {
            return Action::Pause;
        }

        // ── AI scoring ────────────────────────────────────────────────────
        // Build the combined payload for the AI model: path + body.
        // The model sees the same surface the attacker controls.
        let mut ai_payload: Vec<u8> = {
            let mut buf = self.path.as_bytes().to_vec();
            buf.extend_from_slice(&self.body_buffer);
            buf
        };
        // Truncate payload to first 4KB to prevent overwhelming the AI engine
        if ai_payload.len() > 4096 {
            ai_payload.truncate(4096);
        }

        let ai_score = if let Some(score) = self.ai_score {
            score
        } else {
            let max_regex_score = self
                .findings
                .iter()
                .map(|f| f.confidence)
                .fold(0.0_f32, |a, b| a.max(b));

            // Dispatch to python AI if regex score is inconclusive but suspicious
            if max_regex_score >= 0.1 && max_regex_score < self.config.confidence_threshold {
                if !self.dispatched_ai {
                    self.dispatched_ai = true;
                    // Send up to 4KB of payload, plus critical headers
                    let payload_str = String::from_utf8_lossy(&ai_payload).into_owned();
                    let payload_json = serde_json::json!({
                        "payload": payload_str,
                        "user_agent": self.user_agent,
                        "method": self.method,
                        "uri": self.path
                    });

                    let body = payload_json.to_string();

                    match self.dispatch_http_call(
                        "ai_engine_cluster",
                        vec![
                            (":method", "POST"),
                            (":path", "/analyze"),
                            (":authority", "ai-engine"),
                            ("content-type", "application/json"),
                        ],
                        Some(body.as_bytes()),
                        vec![],
                        std::time::Duration::from_millis(100),
                    ) {
                        Ok(_) => return Action::Pause,
                        Err(e) => {
                            log::warn!(
                                target: "neuroguard_waf",
                                "{{\"error\":\"ai_dispatch_failed\",\"detail\":\"{:?}\"}}",
                                e
                            );
                            // Fallback automatically if dispatch fails
                        }
                    }
                }
            }
            // Fallback
            scorer::calculate_risk_score(&ai_payload)
        };

        // Ensure ai_score is captured for findings fallback
        self.ai_score = Some(ai_score);

        if ai_score >= self.config.ai_score_threshold && self.findings.is_empty() {
            use crate::types::{AttackType, ThreatReport};
            self.findings.push(ThreatReport::new(
                AttackType::Unknown,
                ai_score,
                "Semantic Anomaly (AI)".to_string(),
                None,
            ));
        }

        // ── Aggregate decision ────────────────────────────────────────────
        let decision = decision::evaluate(
            &self.findings,
            ai_score,
            self.config.confidence_threshold,
            self.config.ai_score_threshold,
        );

        match decision {
            Decision::Block => {
                self.enforce_block(ai_score);
                Action::Pause
            }
            Decision::Challenge => {
                // v0.1: log and allow. v0.2 will redirect to CAPTCHA.
                if let Some(r) = self.findings.first() {
                    audit_log::log_event(
                        r,
                        &self.method,
                        &self.path,
                        &self.source_ip,
                        &self.user_agent,
                        ai_score,
                        &Decision::Challenge,
                        &self.tenant_id,
                    );
                }
                Action::Continue
            }
            Decision::Allow => {
                log::debug!(
                    target: "neuroguard_waf",
                    "{{\"event\":\"allow\",\"path\":\"{}\"}}",
                    &self.path[..self.path.len().min(128)]
                );
                Action::Continue
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// proxy-wasm trait implementations
// ─────────────────────────────────────────────────────────────────────────────

impl Context for WafHttpContext {
    fn on_http_call_response(
        &mut self,
        _token_id: u32,
        _num_headers: usize,
        body_size: usize,
        _num_trailers: usize,
    ) {
        if let Some(body_bytes) = self.get_http_call_response_body(0, body_size) {
            if let Ok(body_str) = std::str::from_utf8(&body_bytes) {
                // Safely parse JSON instead of manual string parsing which can panic or fail subtly
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(body_str) {
                    if let Some(score) = parsed.get("risk_score").and_then(|v| v.as_f64()) {
                        self.ai_score = Some(score as f32);
                    }
                } else {
                    log::warn!(target: "neuroguard_waf", "{{\"error\":\"ai_response_parse_failed\",\"body\":\"{:.128}\"}}", body_str);
                }
            }
        } else {
            log::warn!(target: "neuroguard_waf", "{{\"error\":\"ai_response_empty\"}}");
        }

        if self.ai_score.is_none() {
            self.ai_score = Some(0.0);
            log::debug!(target: "neuroguard_waf", "{{\"event\":\"ai_fallback\",\"score\":0.0}}");
        }

        self.resume_http_request();
    }
}

impl HttpContext for WafHttpContext {
    // ──────────────────────────────────────────────────────────────────────
    // Phase 1 – Request Headers
    // ──────────────────────────────────────────────────────────────────────

    /// Called when all request headers have been received.
    ///
    /// We perform:
    /// 1. Metadata extraction (IP, method, path, UA).
    /// 2. Bot / scanner UA fingerprinting.
    /// 3. URL path injection scanning (GET-parameter SQLi/XSS).
    ///
    /// Heavy body processing is deferred to `on_http_request_body`.
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        // ── Extract metadata ──────────────────────────────────────────────
        self.method = self.get_http_request_header(":method").unwrap_or_default();
        self.path = self.get_http_request_header(":path").unwrap_or_default();
        self.user_agent = self
            .get_http_request_header("user-agent")
            .unwrap_or_default();
        self.source_ip = self.extract_source_ip();
        self.tenant_id = self
            .get_http_request_header("x-tenant-id")
            .unwrap_or_else(|| "00000000-0000-0000-0000-000000000000".to_string());

        log::debug!(
            target: "neuroguard_waf",
            "{{\"event\":\"headers\",\"method\":\"{}\",\
             \"path\":\"{}\",\"src\":\"{}\"}}",
            self.method,
            &self.path[..self.path.len().min(128)],
            self.source_ip
        );

        // ── Auto-Remediation Blocklist check ──────────────────────────────
        if self.blocklist.borrow().contains(&self.source_ip) {
            self.send_http_response(
                403,
                vec![("content-type", "application/json")],
                Some(
                    b"{\"error\": \"Forbidden\", \"message\": \"IP blocked by Auto-Remediation.\"}",
                ),
            );
            return Action::Pause;
        }

        // ── Bot detection (UA-based) ──────────────────────────────────────
        if self.config.enable_bot_detection {
            if let Some(sets) = &self.detectors {
                if let Some(report) = bot::detect(&self.user_agent, &sets.bot) {
                    // Only block on missing UA if the config says so;
                    // otherwise treat low-confidence bot signals as a challenge.
                    let block_missing_ua =
                        self.user_agent.is_empty() && self.config.block_on_missing_ua;

                    if report.confidence >= self.config.confidence_threshold || block_missing_ua {
                        self.findings.push(report);
                        self.enforce_block(0.0);
                        return Action::Pause;
                    } else {
                        // Low-confidence → accumulate for decision engine
                        self.findings.push(report);
                    }
                }
            }
        }

        // ── URL / path injection scan ─────────────────────────────────────
        // Many SQLi and XSS attacks arrive entirely in the query string.
        // Checking the path in the header phase allows early rejection
        // without buffering a body that may not even exist (GET requests).
        if let Some(sets) = &self.detectors {
            let path = self.path.clone(); // clone to satisfy borrow checker

            if self.config.enable_sqli {
                if let Some(report) = sqli::detect(&path, &sets.sqli) {
                    if report.confidence >= self.config.confidence_threshold {
                        self.findings.push(report);
                        self.enforce_block(0.0);
                        return Action::Pause;
                    }
                    self.findings.push(report);
                }
            }

            if self.config.enable_xss {
                if let Some(report) = xss::detect(&path, &sets.xss) {
                    if report.confidence >= self.config.confidence_threshold {
                        self.findings.push(report);
                        self.enforce_block(0.0);
                        return Action::Pause;
                    }
                    self.findings.push(report);
                }
            }
        }

        Action::Continue
    }

    // ──────────────────────────────────────────────────────────────────────
    // Phase 2 – Request Body
    // ──────────────────────────────────────────────────────────────────────

    /// Called by Envoy for each body chunk. May be called multiple times.
    ///
    /// ## Buffering strategy
    /// We accumulate chunks in `body_buffer`. When `end_of_stream == true`,
    /// the full body is available and we run SQLi + XSS scanning.
    ///
    /// Partial-body analysis would produce false negatives for payloads
    /// deliberately split across chunk boundaries (a known evasion technique).
    ///
    /// ## DoS protection
    /// If buffered + incoming bytes exceed `max_body_bytes` (default 1 MB),
    /// we block immediately without buffering the excess bytes.
    fn on_http_request_body(&mut self, body_size: usize, end_of_stream: bool) -> Action {
        if self.already_blocked {
            return Action::Pause;
        }

        // ── Oversized body guard ──────────────────────────────────────────
        if self.body_buffer.len() + body_size > self.config.max_body_bytes {
            log::warn!(
                target: "neuroguard_waf",
                "{{\"event\":\"body_limit_exceeded\",\
                 \"received\":{},\"limit\":{}}}",
                self.body_buffer.len() + body_size,
                self.config.max_body_bytes
            );
            // A body this large is itself an anomaly. Block it.
            use crate::types::{AttackType, ThreatReport};
            self.findings.push(ThreatReport::new(
                AttackType::Unknown,
                0.95,
                format!(
                    "body_size={} exceeds limit={}",
                    self.body_buffer.len() + body_size,
                    self.config.max_body_bytes
                ),
                None,
            ));
            self.enforce_block(0.0);
            return Action::Pause;
        }

        // ── Buffer the chunk ──────────────────────────────────────────────
        // proxy-wasm gives us the current chunk via get_http_request_body.
        // The offset 0 reads from the start of the current delivery buffer.
        if let Some(chunk) = self.get_http_request_body(0, body_size) {
            self.body_buffer.extend_from_slice(&chunk);
        }

        // ── Wait for the complete body ────────────────────────────────────
        if !end_of_stream {
            return Action::Continue;
        }

        // ── Full body received – run pattern matching ──────────────────────
        log::debug!(
            target: "neuroguard_waf",
            "{{\"event\":\"body_complete\",\"bytes\":{}}}",
            self.body_buffer.len()
        );

        if let Some(sets) = &self.detectors {
            // Convert body to &str for regex matching.
            // Non-UTF-8 bodies are skipped (binary content: images, etc.).
            if let Ok(body_str) = std::str::from_utf8(&self.body_buffer) {
                if self.config.enable_sqli {
                    if let Some(report) = sqli::detect(body_str, &sets.sqli) {
                        self.findings.push(report);
                    }
                }
                if self.config.enable_xss {
                    if let Some(report) = xss::detect(body_str, &sets.xss) {
                        self.findings.push(report);
                    }
                }
            } else {
                log::warn!(
                    target: "neuroguard_waf",
                    "{{\"event\":\"body_non_utf8\",\"bytes\":{}}}",
                    self.body_buffer.len()
                );
            }
        }

        self.run_decision_pipeline()
    }

    // ──────────────────────────────────────────────────────────────────────
    // Phase 3 – Request Trailers
    // ──────────────────────────────────────────────────────────────────────

    /// Called when HTTP/1.1 chunked trailers or HTTP/2 trailing headers arrive.
    ///
    /// Also serves as the safety-net finaliser for body-less requests (GET,
    /// HEAD, DELETE) where `on_http_request_body` never fires with
    /// `end_of_stream == true`.
    fn on_http_request_trailers(&mut self, _num_trailers: usize) -> Action {
        // Idempotent: if body phase already made a decision, respect it.
        self.run_decision_pipeline()
    }
}
