//! # lib.rs – Wasm Entry Point and Module Root
//!
//! This file is the crate root. It:
//! 1. Declares all sub-modules so `rustc` / `wasm-pack` can find them.
//! 2. Registers the root context factory with the proxy-wasm runtime via
//!    `proxy_wasm::set_root_context`.
//! 3. Configures the log level bridged to Envoy's logger.
//!
//! ## Wasm bootstrap sequence
//! ```text
//! Envoy loads .wasm binary
//!   │
//!   └─► _start() called by Wasm runtime
//!         │
//!         ├─► proxy_wasm::set_log_level(Info)
//!         └─► proxy_wasm::set_root_context(factory)
//!                   │
//!                   └─► factory(context_id) → Box<WafRootContext>
//!                             │
//!                             └─► on_vm_start() → parse config + build regexes
//! ```

// ──────────────────────────────────────────────────────────────────────────────
// Crate-level lint policy
// ──────────────────────────────────────────────────────────────────────────────
#![deny(clippy::unwrap_used)] // no unwrap() in production paths
#![deny(clippy::expect_used)] // no expect() in production paths
#![deny(clippy::panic)] // no explicit panics
#![allow(clippy::module_name_repetitions)] // e.g. WafRootContext, WafHttpContext

// ──────────────────────────────────────────────────────────────────────────────
// Sub-module declarations
// ──────────────────────────────────────────────────────────────────────────────
pub mod audit_log;
pub mod blocklist;
pub mod decision;
pub mod detectors;
pub mod http_context;
pub mod root_context;
pub mod types;

pub mod semantic {
    pub mod scorer;
}

#[cfg(not(target_arch = "wasm32"))]
mod proxy_mock;

// ──────────────────────────────────────────────────────────────────────────────
// Wasm entry point
// ──────────────────────────────────────────────────────────────────────────────

use proxy_wasm::traits::RootContext;
use proxy_wasm::types::LogLevel;

/// Entry point called by the Wasm runtime when the module is loaded.
///
/// `#[no_mangle]` preserves the symbol name so Envoy's Wasm host can find it.
/// The `_start` convention is used by both WASI and Envoy's non-WASI Wasm ABI.
///
/// We must NOT perform any heavy work here (no I/O, no pattern compilation).
/// That happens in `WafRootContext::on_vm_start`, which Envoy calls next.
#[cfg_attr(target_arch = "wasm32", export_name = "_start")]
pub fn start() {
    proxy_wasm::set_log_level(LogLevel::Trace);

    proxy_wasm::set_root_context(|_context_id| -> Box<dyn RootContext> {
        Box::new(root_context::WafRootContext::new())
    });
}
