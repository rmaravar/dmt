use sha2::{Sha256, Digest};

pub type HashValue = [u8; 32];  // SHA256 produces a 32-byte hash

pub fn hash_object(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash_bytes: [u8; 32] = hasher.finalize().into();
    hex::encode(hash_bytes)
}

pub fn combined_hash(left: String, right: String) -> String {
    let mut hasher = Sha256::new();
    hasher.update(left.as_bytes());
        hasher.update(right.as_bytes());
    let hash_bytes: [u8; 32] = hasher.finalize().into();
    hex::encode(hash_bytes)
}

pub fn combine_hashes(hashes: Vec<String>) -> String {
    let mut hasher = Sha256::new();
    "".to_string()
}