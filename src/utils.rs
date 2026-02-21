use regex::{RegexSet, RegexSetBuilder};

/// Common utility for structured error logging.
pub fn log_error(context: &str, error: &str) {
    log::error!(
        target: "neuroguard_waf",
        "{{\"event\":\"error\",\"context\":\"{}\",\"detail\":\"{}\"}}",
        context,
        error
    );
}

/// Safely compiles a `RegexSet`, returning an empty set if compilation fails 
/// (to gracefully degrade rather than panicking/crashing the proxy on startup).
pub fn safe_regex_set<I, S>(patterns: I, name: &str, case_insensitive: bool) -> RegexSet
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut builder = RegexSetBuilder::new(patterns);
    builder.case_insensitive(case_insensitive).unicode(false);

    match builder.build() {
        Ok(set) => set,
        Err(e) => {
            log_error(name, &e.to_string());
            // Fallback: an empty RegexSet that matches nothing.
            // Using a simple regex that matches impossible input or an empty set logic.
            match RegexSet::new(std::iter::empty::<&str>()) {
                Ok(empty) => empty,
                Err(e2) => {
                    log_error("fallback_regex_failed", &e2.to_string());
                    // Since panic is disabled and we want to avoid expect/unwrap
                    // This is guaranteed to succeed for an empty iterator in regex crate
                    RegexSetBuilder::new(std::iter::empty::<&str>())
                        .build()
                        .unwrap_or_else(|_| RegexSet::empty())
                }
            }
        }
    }
}
