//! # detectors/sqli.rs – SQL Injection Detector (Full Version with URL Decode)
//!
//! ## regex-lite compatibility notes
//! `regex-lite` does NOT support `\'` or `\"` inside character classes.
//! Use literal `'` and `"` directly. All patterns here are validated
//! against the regex-lite 0.1.x syntax subset.

use crate::types::{sanitise_evidence, AttackType, ThreatReport};
use regex_lite::Regex;

/// All SQLi detection patterns. Index positions are stable for SIEM rule_id.
/// NOTE: character classes use literal ' and " — NOT \' or \" (regex-lite compatible).
pub const SQLI_PATTERNS: &[&str] = &[
    // [0] UNION-based injection
    r"(?i)\bunion\b[\s\+/\*]+(?:all\s+)?select\b",
    // [1] OR tautology – numeric (e.g., 1 OR 1=1)
    r#"(?i)\bor\b\s*['"]?\s*\d+\s*=\s*\d+"#,
    // [2] AND tautology
    r#"(?i)\band\b\s*['"]?\s*\d+\s*=\s*\d+"#,
    // [3] String tautology: ' OR 'x'='x
    r"(?i)'[\s]*or[\s]*'[\w]+'[\s]*=[\s]*'[\w]+'",
    // [4] Stacked DDL/DML after semicolon
    r"(?i);\s*(?:drop|delete|truncate|insert|update|create|alter)\b",
    // [5] Inline comment evasion /**/
    r"/\*[\s\S]{0,50}\*/",
    // [6] Line comment evasion --
    r"--[\s\S]{0,50}",
    // [7] MySQL SLEEP()
    r"(?i)\bsleep\s*\(\s*\d+\s*\)",
    // [8] MSSQL WAITFOR DELAY
    r"(?i)\bwaitfor\s+delay\b",
    // [9] MySQL BENCHMARK()
    r"(?i)\bbenchmark\s*\(\s*\d+",
    // [10] information_schema probing
    r"(?i)\binformation_schema\b",
    // [11] sys.* table probing (MSSQL)
    r"(?i)\bsys\.\w+",
    // [12] Hex-encoding bypass 0x41424344
    r"(?i)\b0x[0-9a-f]{4,}\b",
];

/// Compile the SQLi pattern array into a `Vec<Regex>`.
/// Called ONCE by [`crate::root_context::WafRootContext`] in `on_vm_start`.
pub fn build_sqli_set() -> Result<Vec<Regex>, String> {
    SQLI_PATTERNS
        .iter()
        .enumerate()
        .map(|(i, &p)| Regex::new(p).map_err(|e| format!("SQLi Regex [{i}] build failed: {e}")))
        .collect()
}

/// Helper function to decode URL-encoded strings (e.g., %27 -> ', %20 -> space).
/// This is crucial because attackers often encode payloads to bypass simple filters.
fn url_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    // Only push printable ASCII characters to avoid encoding issues
                    if byte >= 32 && byte < 127 {
                        result.push(byte as char);
                        continue;
                    }
                }
            }
            // If decoding fails or not printable, keep the original %XX
            result.push('%');
            result.push_str(&hex);
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }
    result
}

/// Scan `input` for SQL injection patterns using the pre-compiled `set`.
///
/// Features:
/// 1. Automatically decodes URL-encoded payloads.
/// 2. Checks both original and decoded strings.
/// 3. Includes specific fallback checks for common tautologies like ' OR 1=1.
///
/// Returns `None` if no patterns matched, or `Some(ThreatReport)` with
/// confidence `0.95` (deterministic signature → high confidence).
pub fn detect(input: &str, set: &[Regex]) -> Option<ThreatReport> {
    // Step 1: Decode the input to catch encoded attacks (e.g., %27%20OR%201=1)
    let decoded_input = url_decode(input);

    // We will check both the raw input and the decoded version
    let candidates = vec![input, decoded_input.as_str()];

    for check_str in candidates {
        // Strategy A: Regex Matching
        for (i, re) in set.iter().enumerate() {
            if re.is_match(check_str) {
                let evidence = sanitise_evidence(check_str.as_bytes(), 200);
                return Some(ThreatReport::new(
                    AttackType::SqlInjection,
                    0.95,
                    evidence,
                    Some(i),
                ));
            }
        }

        // Strategy B: Specific Fallback Checks (Case-Insensitive)
        // Catches edge cases that regex might miss due to strict boundaries
        let lower = check_str.to_lowercase();

        // Check for classic ' OR 1=1 variants
        if lower.contains("' or 1=1")
            || lower.contains("' or '1'='1")
            || lower.contains("\" or 1=1")
            || lower.contains("%27 or 1=1")
        // Double check if decode missed something
        {
            let evidence = sanitise_evidence(check_str.as_bytes(), 200);
            return Some(ThreatReport::new(
                AttackType::SqlInjection,
                0.95,
                evidence,
                Some(99), // Special Rule ID for fallback matches
            ));
        }

        // Check for classic UNION SELECT without spaces (using comments)
        if lower.contains("union/**/select") || lower.contains("union%2f%2fselect") {
            let evidence = sanitise_evidence(check_str.as_bytes(), 200);
            return Some(ThreatReport::new(
                AttackType::SqlInjection,
                0.95,
                evidence,
                Some(98),
            ));
        }
    }

    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn get_set() -> Vec<Regex> {
        build_sqli_set().expect("SQLi RegexSet build failed in test")
    }

    #[test]
    fn detects_union_select() {
        assert!(detect("1 UNION SELECT username, password FROM users", &get_set()).is_some());
    }

    #[test]
    fn detects_or_tautology_numeric() {
        for p in &["1 OR 1=1", "1 OR 2=2 --", "1 or 1=1"] {
            assert!(detect(p, &get_set()).is_some(), "missed: {}", p);
        }
    }

    #[test]
    fn detects_or_tautology_string() {
        assert!(detect("' OR '1'='1", &get_set()).is_some());
    }

    #[test]
    fn detects_url_encoded_sqli() {
        // Test case: %27%20OR%201=1  which decodes to ' OR 1=1
        assert!(
            detect("%27%20OR%201=1", &get_set()).is_some(),
            "missed URL encoded payload"
        );
    }

    #[test]
    fn detects_mixed_encoding() {
        // Test case: ' OR 1=1 (raw)
        assert!(
            detect("' OR 1=1", &get_set()).is_some(),
            "missed raw payload"
        );
    }

    #[test]
    fn detects_stacked_drop() {
        assert!(detect("1; DROP TABLE users--", &get_set()).is_some());
    }

    #[test]
    fn detects_sleep() {
        assert!(detect("'; SELECT SLEEP(5)--", &get_set()).is_some());
    }

    #[test]
    fn no_false_positive_on_clean_inputs() {
        let clean = [
            "hello world",
            "user@example.com",
            "2024-01-15",
            "The quick brown fox",
            r#"{"name":"Alice","age":30}"#,
            "SELECT * FROM users WHERE id = 5", // Valid query structure without tautology
        ];
        for input in &clean {
            assert!(
                detect(input, &get_set()).is_none(),
                "false positive: {}",
                input
            );
        }
    }

    #[test]
    fn confidence_is_high() {
        let rep = detect("1 UNION SELECT 1,2,3", &get_set()).expect("must match");
        assert!(rep.confidence >= 0.9);
    }

    #[test]
    fn evidence_truncated_to_200_bytes() {
        let payload = format!("1 UNION SELECT {}", "A".repeat(500));
        let rep = detect(&payload, &get_set()).expect("must match");
        assert!(rep.evidence.len() <= 200);
    }

    #[test]
    fn rule_id_is_populated() {
        let rep = detect("1 UNION SELECT 1,2,3", &get_set()).expect("must match");
        assert!(rep.rule_id.is_some());
    }
}
