//! Implements hashing utilities using SHAKE256, primarily for key generation
//! and other parts of the MAYO signature scheme.

use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
use crate::types::{MessageDigest, Salt, SeedSK, SeedPK};
use crate::params::MayoParams;

/// Generates a fixed-size message digest using SHAKE256.
///
/// # Arguments
/// * `input` - The input byte slice to hash.
/// * `params` - MAYO parameters, used to determine the output `digest_bytes` length.
///
/// # Returns
/// A `MessageDigest` containing the hash output of length `params.digest_bytes`.
pub fn shake256_digest(input: &[u8], params: &MayoParams) -> MessageDigest {
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    let mut digest_bytes_vec = vec![0u8; params.digest_bytes()];
    reader.read(&mut digest_bytes_vec);
    MessageDigest(digest_bytes_vec)
}

/// Derives a public key seed (`SeedPK`) and bytes for the oil space (`O_bytes`)
/// from a secret key seed (`SeedSK`) using SHAKE256 XOF (Extendable Output Function).
///
/// # Arguments
/// * `seed` - The secret key seed (`SeedSK`).
/// * `params` - MAYO parameters, used to determine `pk_seed_bytes` and `O_bytes` lengths.
///
/// # Returns
/// A tuple containing the derived `SeedPK` and a `Vec<u8>` for `O_bytes`.
pub fn shake256_xof_derive_pk_seed_and_o(seed: &SeedSK, params: &MayoParams) -> (SeedPK, Vec<u8>) {
    let mut hasher = Shake256::default();
    hasher.update(&seed.0);
    let mut reader = hasher.finalize_xof();
    
    let mut seedpk_bytes_vec = vec![0u8; params.pk_seed_bytes()];
    reader.read(&mut seedpk_bytes_vec);
    
    let mut o_bytes_vec = vec![0u8; params.o_bytes()]; 
    reader.read(&mut o_bytes_vec);
    
    (SeedPK(seedpk_bytes_vec), o_bytes_vec)
}

/// Derives bytes for the P3 matrix component (`P3_bytes`) from a public key seed (`SeedPK`)
/// using SHAKE256 XOF.
///
/// # Arguments
/// * `seed_pk` - The public key seed (`SeedPK`).
/// * `params` - MAYO parameters, used to determine the `P3_bytes` length.
///
/// # Returns
/// A `Vec<u8>` representing the `P3_bytes`.
pub fn shake256_xof_derive_p3(seed_pk: &SeedPK, params: &MayoParams) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(&seed_pk.0);
    let mut reader = hasher.finalize_xof();
    let mut p3_bytes_vec = vec![0u8; params.p3_bytes()];
    reader.read(&mut p3_bytes_vec);
    p3_bytes_vec
}

/// Derives the target vector `t` from a message digest (`M_digest`) and a salt (`Salt`)
/// using SHAKE256 XOF. The output length is determined by `params.m` (number of equations),
/// considering that each element of `t` is in GF(16) (4 bits).
///
/// # Arguments
/// * `m_digest` - The message digest.
/// * `salt` - The salt.
/// * `params` - MAYO parameters, specifically `params.m` to determine output length.
///
/// # Returns
/// A `Vec<u8>` representing the target vector `t`, with a length of `ceil(m/2)` bytes.
pub fn shake256_derive_target_t(m_digest: &MessageDigest, salt: &Salt, params: &MayoParams) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(&m_digest.0);
    hasher.update(&salt.0);
    let mut reader = hasher.finalize_xof();
    
    // Each element of t is in GF(q). For q=16, each element is 4 bits.
    // The target vector t has m elements. So, m * 4 bits = m/2 bytes.
    // If m is odd, we need (m+1)/2 bytes to store m nibbles.
    let target_len_bytes = MayoParams::bytes_for_gf16_elements(params.m());
    let mut t_bytes_vec = vec![0u8; target_len_bytes];
    reader.read(&mut t_bytes_vec);
    t_bytes_vec
}
