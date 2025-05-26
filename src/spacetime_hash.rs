//! Implements Blake2b-512 hashing for CompactSecretKey.
use wasm_bindgen::prelude::*;

use crate::types::CompactSecretKey;
use blake2::{Blake2b512, Digest};

/// Hashes a CompactSecretKey (which is a seedsk) using Blake2b-512.
/// Returns a 64-byte hash.
#[wasm_bindgen]
pub fn hash_compact_secret_key(csk: &CompactSecretKey) -> Vec<u8> {
    let mut hasher = Blake2b512::new();
    hasher.update(&csk.0); // csk.0 is Vec<u8> representing seedsk
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::MayoParams; // To use for keypair generation
    use crate::keygen::compact_key_gen; // To generate a csk

    #[test]
    fn test_hash_csk() {
        // Create a dummy CompactSecretKey using keypair for MAYO1
        let params_mayo1 = MayoParams::mayo1();
        let (csk1, _cpk1) = compact_key_gen(&params_mayo1)
            .expect("Failed to generate csk1 for testing hash");

        // Call hash_compact_secret_key
        let hash1 = hash_compact_secret_key(&csk1);

        // Assert that the output hash has the correct length (64 bytes for Blake2b512)
        assert_eq!(hash1.len(), 64, "Hash output length is incorrect for Blake2b512");

        // Assert that hashing the same csk again produces the same hash
        let hash1_again = hash_compact_secret_key(&csk1);
        assert_eq!(hash1, hash1_again, "Hashing the same CSK should produce the same hash");

        // Assert that hashing a different csk produces a different hash
        // Create another CSK (e.g., for MAYO1 again, or MAYO2)
        // Using keypair ensures it's different due to randomness in seed generation
        let (csk2, _cpk2) = compact_key_gen(&params_mayo1)
            .expect("Failed to generate csk2 for testing hash");
        
        // Ensure csk1 and csk2 are actually different before hashing
        // This is highly probable due to random seed generation.
        if csk1.0 == csk2.0 {
            // In the extremely unlikely event of a seed collision, try one more time.
            // This is mostly to make the test robust against theoretical collisions.
            let (csk_temp, _) = compact_key_gen(&params_mayo1).unwrap();
            if csk_temp.0 != csk1.0 {
                 // Use csk_temp if it's different
                 let hash2 = hash_compact_secret_key(&csk_temp);
                 assert_ne!(hash1, hash2, "Hashes of different CSKs should be different (after retry)");
            } else {
                // If still a collision (astronomically unlikely), we can't effectively test "different hash"
                // without mocking getrandom or having more deterministic CSK inputs for testing.
                // For this test, we'll assume getrandom provides different seeds.
                // If this part of the test is flaky, it points to issues in keygen or randomness.
                let hash2 = hash_compact_secret_key(&csk2); // Proceed with potentially same csk2
                if csk1.0 != csk2.0 { // Only assert if they were truly different
                    assert_ne!(hash1, hash2, "Hashes of different CSKs should be different");
                } else {
                    // If they are identical after two attempts, we can't test the "different hash" property here.
                    // This is more of a keygen test at this point.
                    println!("Warning: CSKs were identical after multiple generation attempts; cannot fully test 'different hash' property of hash_compact_secret_key.");
                }
            }
        } else {
            let hash2 = hash_compact_secret_key(&csk2);
            assert_ne!(hash1, hash2, "Hashes of different CSKs should be different");
        }


        // Test with a fixed known CSK to ensure deterministic output if needed,
        // but this requires a known hash value. For now, properties are tested.
        let fixed_csk_data = vec![0u8; params_mayo1.sk_seed_bytes()]; // e.g., all zeros
        let fixed_csk = CompactSecretKey(fixed_csk_data);
        let _fixed_hash = hash_compact_secret_key(&fixed_csk);
        // To make this a strong assertion, one would need to precompute the hash of `fixed_csk_data`.
        // e.g. assert_eq!(fixed_hash, PRECOMPUTED_HASH_OF_ZEROS_SK_SEED_BYTES);
    }
}
