// ============================================================
// core/dedupe.rs — Result deduplication
// ============================================================

#[allow(dead_code)]
pub fn deduplicate_strings(input: Vec<String>) -> Vec<String> {
    let mut v = input;
    v.sort();
    v.dedup();
    v
}
