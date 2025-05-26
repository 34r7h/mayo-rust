//! Implements AES-128-CTR based pseudo-random byte generation,
//! primarily for deriving P1 and P2 matrix components in MAYO.

use aes::Aes128;
use aes::cipher::{generic_array::GenericArray, StreamCipher, KeyIvInit}; // Removed KeyInit
use ctr::Ctr128BE; // Using Big Endian as is common in cryptographic contexts.
use crate::types::SeedPK;
use crate::params::MayoVariantParams;

/// Generates a stream of pseudo-random bytes using AES-128-CTR.
///
/// The AES key is derived from `key_bytes` (typically `seed_pk.0`).
/// A standard zero IV (nonce) is used for the start of the CTR mode.
///
/// # Arguments
/// * `key_bytes` - A 16-byte slice representing the AES-128 key.
/// * `output_len` - The number of pseudo-random bytes to generate.
///
/// # Panics
/// Panics if `key_bytes` is not 16 bytes long. This is a simplification for this subtask;
/// a production implementation should return a `Result`.
///
/// # Returns
/// A `Vec<u8>` containing the generated pseudo-random bytes.
fn aes128_ctr_generate(key_bytes: &[u8], output_len: usize) -> Vec<u8> {
    if key_bytes.len() != 16 {
        // In a real library, this should be an error type.
        // Aes128::new itself would also panic or error on incorrect key length.
        panic!("AES-128 key must be 16 bytes. Provided key length: {}", key_bytes.len());
    }
    let key = GenericArray::from_slice(key_bytes);
    let iv = GenericArray::from_slice(&[0u8; 16]); // Standard zero IV for CTR start

    // Ctr128BE<Aes128> implements the StreamCipher trait.
    let mut cipher = Ctr128BE::<Aes128>::new(key, iv);
    
    let mut output = vec![0u8; output_len];
    cipher.apply_keystream(&mut output);
    
    output
}

/// Derives the bytes for the P1 matrix component from a public key seed (`SeedPK`)
/// using AES-128-CTR.
///
/// # Arguments
/// * `seed_pk` - The public key seed, which provides the 16-byte key for AES.
/// * `params` - The MAYO variant parameters, used to determine `params.p1_bytes`.
///
/// # Returns
/// A `Vec<u8>` representing the derived `P1_bytes`.
pub fn derive_p1_bytes(seed_pk: &SeedPK, params: &MayoVariantParams) -> Vec<u8> {
    if seed_pk.0.len() != params.pk_seed_bytes {
        // Ensure seed_pk length matches expected key size from params
        // This also implicitly checks if pk_seed_bytes is 16 for AES-128
        panic!("SeedPK length {} does not match params.pk_seed_bytes {} for AES-128 key", 
               seed_pk.0.len(), params.pk_seed_bytes);
    }
    aes128_ctr_generate(&seed_pk.0, params.p1_bytes)
}

/// Derives the bytes for the P2 matrix component from a public key seed (`SeedPK`)
/// using AES-128-CTR.
///
/// # Arguments
/// * `seed_pk` - The public key seed, which provides the 16-byte key for AES.
/// * `params` - The MAYO variant parameters, used to determine `params.p2_bytes`.
///
/// # Returns
/// A `Vec<u8>` representing the derived `P2_bytes`.
pub fn derive_p2_bytes(seed_pk: &SeedPK, params: &MayoVariantParams) -> Vec<u8> {
    if seed_pk.0.len() != params.pk_seed_bytes {
        panic!("SeedPK length {} does not match params.pk_seed_bytes {} for AES-128 key", 
               seed_pk.0.len(), params.pk_seed_bytes);
    }
    aes128_ctr_generate(&seed_pk.0, params.p2_bytes)
}
