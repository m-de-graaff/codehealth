use sha2::{Digest, Sha256};
use xxhash_rust::xxh3::xxh3_64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyFingerprint {
    pub fast_hash: u64,
    pub stable_hash_hex: String,
}

pub fn fingerprint_normalized_body(source: &str) -> BodyFingerprint {
    let normalized = normalize_whitespace(source);
    let stable_hash = Sha256::digest(normalized.as_bytes());

    BodyFingerprint {
        fast_hash: xxh3_64(normalized.as_bytes()),
        stable_hash_hex: format!("{stable_hash:x}"),
    }
}

fn normalize_whitespace(source: &str) -> String {
    source.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_ignores_whitespace_changes() {
        let left = fingerprint_normalized_body("return   value");
        let right = fingerprint_normalized_body("return value");

        assert_eq!(left, right);
    }
}
