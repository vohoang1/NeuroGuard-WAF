//! # root_context.rs – WAF Root Context (per Wasm VM)
//!
//! `WafRootContext` is instantiated once per Envoy worker thread (one Wasm
//! VM per thread). It owns all shared, long-lived state:
//!
//! - Parsed [`WafConfig`] loaded from Envoy's plugin configuration.
//! - Pre-compiled [`DetectorSets`] (regex pattern sets for SQLi, XSS, bot).
//!
//! Every incoming HTTP request gets a new [`WafHttpContext`] (created by
//! `create_http_context`), which receives immutable references into the
//! root context's compiled state rather than recompiling patterns itself.
//!
//! ## Thread safety
//! Envoy's Wasm runtime is single-threaded per VM. No `Arc<Mutex<_>>`
//! wrappers are needed. The Rust borrow checker enforces the invariants
//! at compile time.

use crate::blocklist::BlocklistResponse;
use crate::detectors::DetectorSets;
use crate::http_context::WafHttpContext;
use crate::types::WafConfig;
use proxy_wasm::traits::{Context, HttpContext, RootContext};
use proxy_wasm::types::ContextType;
use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;
use std::time::Duration;

// ─────────────────────────────────────────────────────────────────────────────
// Root context struct
// ─────────────────────────────────────────────────────────────────────────────

pub struct WafRootContext {
    /// Parsed operator configuration. Defaults are safe if no config provided.
    config: WafConfig,

    /// Pre-compiled regex sets. `Option` because they are built in
    /// `on_vm_start`; the field is `None` only before that hook fires.
    detectors: Option<DetectorSets>,

    /// Auto-blocking cache
    blocklist: Rc<RefCell<HashSet<String>>>,
}

impl WafRootContext {
    pub fn new() -> Self {
        Self {
            config: WafConfig::default(),
            detectors: None,
            blocklist: Rc::new(RefCell::new(HashSet::new())),
        }
    }
}

// proxy-wasm requires `Context` to also be implemented (base trait).
impl Context for WafRootContext {
    fn on_http_call_response(
        &mut self,
        _token_id: u32,
        _num_headers: usize,
        body_size: usize,
        _num_trailers: usize,
    ) {
        if let Some(body) = self.get_http_call_response_body(0, body_size) {
            if let Ok(resp) = serde_json::from_slice::<BlocklistResponse>(&body) {
                let mut b = self.blocklist.borrow_mut();
                b.clear();
                for ip in resp.blocked_ips {
                    b.insert(ip);
                }
                log::debug!(target: "neuroguard_waf", "{{\"event\":\"blocklist_updated\",\"count\":{}}}", b.len());
            }
        }
    }
}

impl RootContext for WafRootContext {
    /// Called once by Envoy immediately after the Wasm VM is instantiated,
    /// before any HTTP traffic is processed.
    ///
    /// Responsibilities:
    /// 1. Read and parse the JSON plugin configuration.
    /// 2. Compile all regex pattern sets and store them in `self.detectors`.
    ///
    /// Returning `false` would prevent the VM from starting; we always
    /// return `true` and fall back to safe defaults on any error, rather
    /// than dropping all traffic on this worker.
    fn on_vm_start(&mut self, _configuration_size: usize) -> bool {
        log::info!(target: "neuroguard_waf", "{{\"event\":\"vm_start\"}}");

        // Compile regex pattern sets once during VM startup.
        match DetectorSets::build() {
            Ok(sets) => {
                log::info!(
                    target: "neuroguard_waf",
                    "{{\"event\":\"detectors_ready\",\"sqli\":{},\"xss\":{},\"bot\":{}}}",
                    crate::detectors::sqli::SQLI_PATTERNS.len(),
                    crate::detectors::xss::XSS_PATTERNS.len(),
                    crate::detectors::bot::BOT_UA_PATTERNS.len(),
                );
                self.detectors = Some(sets);
            }
            Err(e) => {
                log::error!(target: "neuroguard_waf", "{{\"event\":\"detector_build_failed\",\"detail\":\"{}\"}}", e);
            }
        }

        self.set_tick_period(Duration::from_secs(15));

        true
    }

    fn on_tick(&mut self) {
        self.dispatch_http_call(
            "backend_api_cluster",
            vec![
                (":method", "GET"),
                (":path", "/api/internal/blocklist"),
                (":authority", "neuroguard-api:8081"),
            ],
            None,
            vec![],
            Duration::from_secs(5),
        ).unwrap_or_else(|e| {
            log::error!(target: "neuroguard_waf", "Failed to dispatch http call for blocklist: {:?}", e);
            0
        });
    }

    fn on_configure(&mut self, configuration_size: usize) -> bool {
        log::info!(target: "neuroguard_waf", "{{\"event\":\"on_configure\",\"size\":{}}}", configuration_size);
        if configuration_size > 0 {
            if let Some(bytes) = self.get_plugin_configuration() {
                match serde_json::from_slice::<WafConfig>(&bytes) {
                    Ok(cfg) => {
                        self.config = WafConfig {
                            max_body_bytes: cfg.max_body_bytes.min(1024 * 1024),
                            ..cfg
                        };
                        log::info!(
                            target: "neuroguard_waf",
                            "{{\"event\":\"config_loaded\",\"sqli\":{},\"xss\":{},\"bot\":{},\"max_body_bytes\":{}}}",
                            self.config.enable_sqli,
                            self.config.enable_xss,
                            self.config.enable_bot_detection,
                            self.config.max_body_bytes
                        );
                    }
                    Err(e) => {
                        log::error!(target: "neuroguard_waf", "{{\"event\":\"config_parse_error\",\"detail\":\"{}\"}}", e);
                    }
                }
            }
        }
        true
    }

    /// Tell the SDK we want to intercept HTTP streams.
    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }

    /// Factory method: called by the SDK for every new HTTP request.
    ///
    /// We pass the config and detector references by value/clone.
    /// Config is a small struct (cheap clone). `DetectorSets` contains
    /// `RegexSet` which is internally reference-counted, so the clone
    /// is O(1) and shares the underlying compiled DFA.
    fn create_http_context(&self, context_id: u32) -> Option<Box<dyn HttpContext>> {
        log::debug!(
            target: "neuroguard_waf",
            "{{\"event\":\"http_context_create\",\"context_id\":{}}}",
            context_id
        );

        // If detectors failed to build, we create an HTTP context with
        // no detection capability (fail-open). The alternative – returning
        // `None` – would cause Envoy to skip this filter entirely.
        Some(Box::new(WafHttpContext::new(
            self.config.clone(),
            // Clone the Arc-backed RegexSets (cheap)
            self.detectors.as_ref().and_then(|d| {
                // Rebuild a DetectorSets from the existing compiled sets.
                // RegexSet implements Clone, so this is a cheap refcount bump.
                Some(DetectorSets {
                    sqli: d.sqli.clone(),
                    xss: d.xss.clone(),
                    bot: d.bot.clone(),
                })
            }),
            self.blocklist.clone(),
        )))
    }
}
