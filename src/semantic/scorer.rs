//! # semantic/scorer.rs – AI Risk Scoring Stage
//!
//! This module is the integration point for the ONNX-based semantic analysis
//! model. In v0.1, `calculate_risk_score` returns `0.0` (safe) unconditionally.
//!
//! ## Future integration path (v0.2+)
//!
//! 1. **Model loading** – The ONNX model binary will be delivered via Envoy's
//!    shared data plane (`get_shared_data("waf_model_v1")`). The root context
//!    will call `load_model()` in `on_vm_start` and store the session handle.
//!
//! 2. **Feature extraction** – `preprocess(payload)` will tokenise the raw
//!    bytes using a byte-pair encoding (BPE) vocabulary trained on HTTP traffic.
//!    Output: a fixed-length `[f32; 512]` embedding vector.
//!
//! 3. **Inference** – The `ort` crate (ONNX Runtime Rust bindings, compiled to
//!    `wasm32-wasi`) will run the model synchronously inside the Wasm sandbox.
//!    The model output is a single sigmoid logit → cast to f32 risk score.
//!
//! 4. **Latency** – Inference budget is 1.0 ms. If the runtime reports latency
//!    above budget (measured via `proxy_wasm::hostcalls::get_current_time_ns`),
//!    a flag is set and the score falls back to 0.0 to avoid adding latency.
//!
//! ```rust,ignore
//! // ── Pseudocode for v0.2 integration ──────────────────────────────────────
//!
//! use ort::{Environment, Session, Value};
//!
//! pub struct OnnxScorer {
//!     session: Session,
//! }
//!
//! impl OnnxScorer {
//!     pub fn from_bytes(model_bytes: &[u8]) -> Result<Self, ort::Error> {
//!         let env = Environment::builder().build()?;
//!         let session = env.new_session_builder()?.with_model_from_memory(model_bytes)?;
//!         Ok(Self { session })
//!     }
//!
//!     pub fn score(&self, payload: &[u8]) -> f32 {
//!         let embedding = preprocess(payload);          // → [f32; 512]
//!         let input = Value::from_array(embedding);
//!         let outputs = self.session.run(vec![input]).unwrap_or_default();
//!         sigmoid(outputs[0].try_extract::<f32>().unwrap_or(0.0))
//!     }
//! }
//!
//! fn sigmoid(x: f32) -> f32 { 1.0 / (1.0 + (-x).exp()) }
//! ```

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Calculate a semantic risk score for the given request payload.
///
/// ## Input
/// `payload` is the concatenation of the URL path bytes and the buffered
/// request body bytes. The caller is responsible for pre-truncation to the
/// configured body limit so this function never receives more than 1 MB.
///
/// ## Output
/// A `f32` in `[0.0, 1.0]`:
/// - `0.0` → definitively safe (model is confident).
/// - `1.0` → definitively malicious.
/// - Values between 0 and 1 reflect model uncertainty.
///
/// The calling [`crate::decision::evaluate`] function blocks the request
/// when this score exceeds `WafConfig.ai_score_threshold` (default 0.8).
///
/// ## Current implementation (v0.1 stub)
/// Returns `0.0` unconditionally. The function signature, doc contract,
/// and position in the pipeline are frozen so the ONNX model can be
/// dropped in by changing only this function's body.
///
/// ## Non-blocking guarantee
/// This function MUST NOT perform any I/O or host calls. In the Wasm
/// execution model, all host interactions go through the proxy-wasm ABI.
/// The ONNX inference engine runs entirely within Wasm linear memory.
#[inline]
pub fn calculate_risk_score(_payload: &[u8]) -> f32 {
    // ── ONNX model inference will replace this line in v0.2 ──────────────
    //
    // Returning 0.0 means the AI stage never independently triggers a block
    // in the current version. All blocking is driven by the signature
    // detectors (sqli, xss, bot) in this release.
    0.0
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_returns_zero_for_clean_payload() {
        let score = calculate_risk_score(b"Hello, world!");
        assert!((score - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn stub_returns_zero_for_malicious_looking_payload() {
        // Confirms the stub doesn't accidentally produce non-zero values.
        let score = calculate_risk_score(b"' OR 1=1 -- UNION SELECT * FROM users");
        assert!((score - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn score_is_within_valid_range() {
        let score = calculate_risk_score(b"<script>alert(1)</script>");
        assert!((0.0..=1.0).contains(&score), "score must be in [0.0, 1.0]");
    }

    #[test]
    fn score_handles_empty_payload() {
        let score = calculate_risk_score(b"");
        assert!((score - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn score_handles_large_payload() {
        let large = vec![b'A'; 1024 * 1024]; // 1 MB
        let score  = calculate_risk_score(&large);
        assert!((0.0..=1.0).contains(&score));
    }
}