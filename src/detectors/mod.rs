//! # detectors/mod.rs – Detector Module Registry
//!
//! Re-exports each detector sub-module and provides the compiled
//! `RegexSet` collection type that the root context stores and passes
//! to each HTTP context at request time.

pub mod bot;
pub mod sqli;
pub mod xss;

use regex_lite::Regex;

/// All pre-compiled pattern sets owned by the root context.
///
/// Stored as a struct so it can be passed by reference to HTTP contexts
/// without any additional heap allocation per request.
///
/// Built once in `WafRootContext::on_vm_start` via `DetectorSets::build()`.
pub struct DetectorSets {
    pub sqli: Vec<Regex>,
    pub xss: Vec<Regex>,
    pub bot: Vec<Regex>,
}

impl DetectorSets {
    /// Compile all detector pattern sets.
    ///
    /// Returns a descriptive error string if any pattern is invalid.
    /// Called exactly once per Wasm VM during `on_vm_start`.
    pub fn build() -> Result<Self, String> {
        Ok(Self {
            sqli: sqli::build_sqli_set()?,
            xss: xss::build_xss_set()?,
            bot: bot::build_bot_set()?,
        })
    }
}
