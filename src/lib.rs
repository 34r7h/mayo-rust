// use wasm_bindgen::prelude::*; // Removed as per compiler warning
// use blake2::{Blake2b512, Digest}; // Removed as per compiler warning

pub mod params;
pub mod types;
pub mod hash;
pub mod aes_ctr;
pub mod gf;
pub mod matrix;
pub mod codec;
pub mod keygen;
pub mod solver;
pub mod sign;
pub mod verify;

pub mod api;
pub use api::{keypair, sign, open};

pub mod spacetime_hash;
pub use spacetime_hash::hash_compact_secret_key;

// Placeholder for any top-level library functions or re-exports if needed in the future.

// The old Mayo functions (generate_keypair, sign_message, verify_signature, hash_secret_key)
// and their associated tests have been removed as they were based on an incorrect 'mayo' crate.
// New implementations will be based on the structures in `params.rs` and `types.rs`.

#[cfg(test)]
mod tests {
    // TODO: Add new tests specific to the new params and types,
    // and eventually the actual MAYO cryptographic operations.
    #[test]
    fn it_works_stub() {
        assert_eq!(2 + 2, 4);
    }
}
