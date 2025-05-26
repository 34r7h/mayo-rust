//! Implements MAYO Compact Key Generation (Algorithm 5), Secret Key Expansion (Algorithm 6), and Public Key Expansion (Algorithm 7).

use crate::types::{CompactSecretKey, CompactPublicKey, ExpandedSecretKey, ExpandedPublicKey, SeedSK, SeedPK, GFMatrix, GFVector};
use crate::params::{MayoParams}; // MayoVariantParams is accessed via MayoParams.variant()
use crate::hash::{shake256_xof_derive_pk_seed_and_o, shake256_xof_derive_p3};
use crate::codec::{decode_o_matrix, decode_p1_matrices, decode_p2_matrices, encode_gf_elements};
use crate::aes_ctr::{derive_p1_bytes, derive_p2_bytes};
use crate::matrix::{matrix_add, matrix_transpose, matrix_mul};
use getrandom::getrandom;

/// Implements MAYO.CompactKeyGen (Algorithm 5 from the MAYO specification).
/// Generates a compact secret key (csk) and a compact public key (cpk).
///
/// # Arguments
/// * `params_enum` - A reference to `MayoParams` enum, which specifies the MAYO variant (e.g., MAYO1, MAYO2).
///
/// # Returns
/// `Ok((CompactSecretKey, CompactPublicKey))` if successful.
/// `Err(&'static str)` if random number generation fails or if derived byte lengths are inconsistent.
pub fn compact_key_gen(params_enum: &MayoParams) -> Result<(CompactSecretKey, CompactPublicKey), &'static str> {
    let params = params_enum.variant(); // Get MayoVariantParams

    // 1. Generate a random secret key seed (seed_sk)
    //    seed_sk <-$_R {0,1}^(lambda_seed)  (lambda_seed = params.sk_seed_bytes * 8)
    let mut seedsk_bytes = vec![0u8; params.sk_seed_bytes];
    getrandom(&mut seedsk_bytes).map_err(|_| "Failed to generate random seedsk")?;
    let seedsk = SeedSK(seedsk_bytes);

    // 2. Derive seed_pk and O_bytes from seed_sk using SHAKE256
    //    (seed_pk || O_bytes) = SHAKE256(seed_sk, params.pk_seed_bytes + params.O_bytes)
    //    The shake256_xof_derive_pk_seed_and_o function handles this logic.
    //    O_bytes itself isn't directly part of the simplified csk/cpk here, but is derived.
    let (seedpk, _o_bytes) = shake256_xof_derive_pk_seed_and_o(&seedsk, params_enum);

    // 3. Derive P3_bytes from seed_pk using SHAKE256
    //    P3_bytes = SHAKE256(seed_pk, params.P3_bytes)
    //    The shake256_xof_derive_p3 function handles this.
    let p3_bytes = shake256_xof_derive_p3(&seedpk, params_enum);
    
    // Ensure derived P3_bytes has the expected length as defined in params.
    // This check is good practice, though shake256_xof_derive_p3 should already produce correct length.
    if p3_bytes.len() != params.p3_bytes {
         return Err("Derived P3_bytes length does not match params.p3_bytes");
    }

    // 4. Construct csk (CompactSecretKey is just SeedSK)
    //    csk = seed_sk
    let csk = CompactSecretKey(seedsk.0); // .0 extracts the Vec<u8> from SeedSK

    // 5. Construct cpk (CompactPublicKey is seed_pk || P3_bytes)
    //    cpk = seed_pk || P3_bytes
    let mut cpk_bytes = Vec::with_capacity(params.pk_seed_bytes + params.p3_bytes);
    cpk_bytes.extend_from_slice(&seedpk.0); // .0 extracts Vec<u8> from SeedPK
    cpk_bytes.extend_from_slice(&p3_bytes);
    let cpk = CompactPublicKey(cpk_bytes);

    Ok((csk, cpk))
}

/// Implements MAYO.ExpandSK (Algorithm 6 from the MAYO specification).
/// Expands a compact secret key (csk) into an expanded secret key (esk).
pub fn expand_sk(csk: &CompactSecretKey, params_enum: &MayoParams) -> Result<ExpandedSecretKey, &'static str> {
    let params = params_enum.variant();
    
    // 1. Parse csk to get seedsk (csk is effectively seedsk)
    let seedsk = SeedSK(csk.0.clone()); // csk.0 is Vec<u8>

    // 2. Derive seedpk and O_bytes from seedsk
    let (seedpk, o_bytes) = shake256_xof_derive_pk_seed_and_o(&seedsk, params_enum);
    if o_bytes.len() != params.o_bytes {
        return Err("O_bytes length mismatch during derivation");
    }

    // 3. Decode O_bytes into matrix O
    let o_matrix = decode_o_matrix(&o_bytes, params)?;

    // 4. Derive P1_all_bytes and P2_all_bytes from seedpk
    let p1_all_bytes = derive_p1_bytes(&seedpk, params);
    if p1_all_bytes.len() != params.p1_bytes {
         return Err("P1_bytes length mismatch during derivation");
    }
    let p2_all_bytes = derive_p2_bytes(&seedpk, params);
     if p2_all_bytes.len() != params.p2_bytes {
         return Err("P2_bytes length mismatch during derivation");
    }

    // 5. Decode P1_all_bytes and P2_all_bytes into matrices {P(1)i} and {P(2)i}
    let p1_matrices = decode_p1_matrices(&p1_all_bytes, params)?;
    let p2_matrices = decode_p2_matrices(&p2_all_bytes, params)?;

    if p1_matrices.len() != params.m || p2_matrices.len() != params.m {
        return Err("Incorrect number of P1 or P2 matrices decoded");
    }

    // 6. Compute secret matrices Li
    let mut l_matrices: Vec<GFMatrix> = Vec::with_capacity(params.m);
    for i in 0..params.m {
        let p1_i = &p1_matrices[i];
        let p1_i_t = matrix_transpose(p1_i);
        // P(1)i + P(1)Ti
        let sum_p1_p1t = matrix_add(p1_i, &p1_i_t)?; 
        // (P(1)i + P(1)Ti)O
        let term1 = matrix_mul(&sum_p1_p1t, &o_matrix)?;
        // Li = (P(1)i + P(1)Ti)O + P(2)i
        let l_i = matrix_add(&term1, &p2_matrices[i])?;
        l_matrices.push(l_i);
    }

    // Flatten all L matrices into one long GFVector then encode.
    let mut l_elements_flat: GFVector = Vec::new();
    for l_i in &l_matrices {
        l_elements_flat.extend_from_slice(&l_i.data);
    }
    let l_all_bytes = encode_gf_elements(&l_elements_flat);
    let expected_l_elements = params.m * (params.n - params.o) * (params.n - params.o);
    let expected_l_bytes_len = MayoParams::bytes_for_gf16_elements(expected_l_elements);
    if l_all_bytes.len() != expected_l_bytes_len {
        return Err("L_all_bytes length mismatch during encoding");
    }

    // 8. Construct esk: seedsk || O_bytes || P1_all_bytes || l_all_bytes
    let mut esk_bytes = Vec::new();
    esk_bytes.extend_from_slice(&seedsk.0);
    esk_bytes.extend_from_slice(&o_bytes);
    esk_bytes.extend_from_slice(&p1_all_bytes);
    esk_bytes.extend_from_slice(&l_all_bytes);
    
    Ok(ExpandedSecretKey(esk_bytes))
}

/// Implements MAYO.ExpandPK (Algorithm 7 from the MAYO specification).
/// Expands a compact public key (cpk) into an expanded public key (epk).
pub fn expand_pk(cpk: &CompactPublicKey, params_enum: &MayoParams) -> Result<ExpandedPublicKey, &'static str> {
    let params = params_enum.variant();

    // 1. Parse cpk to extract seedpk and P3_byte_string
    if cpk.0.len() != params.pk_seed_bytes + params.p3_bytes {
        return Err("Compact public key has incorrect length");
    }
    let seedpk_bytes = &cpk.0[0..params.pk_seed_bytes];
    let p3_all_bytes_from_cpk = &cpk.0[params.pk_seed_bytes..];
    
    let seedpk = SeedPK(seedpk_bytes.to_vec());

    // 2. Derive P1_all_bytes and P2_all_bytes from seedpk
    let p1_all_bytes = derive_p1_bytes(&seedpk, params);
    if p1_all_bytes.len() != params.p1_bytes {
            return Err("P1_bytes length mismatch during derivation");
    }
    let p2_all_bytes = derive_p2_bytes(&seedpk, params);
    if p2_all_bytes.len() != params.p2_bytes {
            return Err("P2_bytes length mismatch during derivation");
    }

    // 3. Construct epk: P1_all_bytes || P2_all_bytes || P3_all_bytes_from_cpk
    let mut epk_bytes = Vec::with_capacity(params.p1_bytes + params.p2_bytes + params.p3_bytes);
    epk_bytes.extend_from_slice(&p1_all_bytes);
    epk_bytes.extend_from_slice(&p2_all_bytes);
    epk_bytes.extend_from_slice(p3_all_bytes_from_cpk);
    
    Ok(ExpandedPublicKey(epk_bytes))
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::MayoParams;

    fn test_compact_keygen_for_variant(params_enum: &MayoParams) {
        let params_variant = params_enum.variant();
        let res = compact_key_gen(params_enum);
        assert!(res.is_ok());
        let (csk, cpk) = res.unwrap();

        // Test csk length
        assert_eq!(csk.0.len(), params_variant.sk_seed_bytes, 
                   "CSK length mismatch for variant");

        // Test cpk length
        assert_eq!(cpk.0.len(), params_variant.pk_seed_bytes + params_variant.p3_bytes,
                   "CPK length mismatch for variant");

        // Test that subsequent calls produce different keys (probabilistic test for randomness)
        let res2 = compact_key_gen(params_enum);
        assert!(res2.is_ok());
        let (csk2, cpk2) = res2.unwrap();

        assert_ne!(csk.0, csk2.0, "CSKs from subsequent calls should be different");
        assert_ne!(cpk.0, cpk2.0, "CPKs from subsequent calls should be different");
    }

    #[test]
    fn test_compact_keygen_mayo1() {
        test_compact_keygen_for_variant(&MayoParams::mayo1());
    }

    #[test]
    fn test_compact_keygen_mayo2() {
        test_compact_keygen_for_variant(&MayoParams::mayo2());
    }

    #[test]
    fn test_key_component_lengths_explicit_mayo1() {
        // This test is more about verifying my understanding of the parameter values from Turn 37
        let params_mayo1 = MayoParams::mayo1();
        let variant_params = params_mayo1.variant();

        // From params.rs for MAYO1:
        // sk_seed_bytes: 24
        // pk_seed_bytes: 16
        // p3_bytes: 1152
        assert_eq!(variant_params.sk_seed_bytes, 24);
        assert_eq!(variant_params.pk_seed_bytes, 16);
        assert_eq!(variant_params.p3_bytes, 1152);
        
        let (csk, cpk) = compact_key_gen(&params_mayo1).unwrap();
        assert_eq!(csk.0.len(), 24);
        assert_eq!(cpk.0.len(), 16 + 1152);
    }

    #[test]
    fn test_key_component_lengths_explicit_mayo2() {
        let params_mayo2 = MayoParams::mayo2();
        let variant_params = params_mayo2.variant();
        
        // From params.rs for MAYO2:
        // sk_seed_bytes: 24
        // pk_seed_bytes: 16
        // p3_bytes: 10944
        assert_eq!(variant_params.sk_seed_bytes, 24);
        assert_eq!(variant_params.pk_seed_bytes, 16);
        assert_eq!(variant_params.p3_bytes, 10944);

        let (csk, cpk) = compact_key_gen(&params_mayo2).unwrap();
        assert_eq!(csk.0.len(), 24);
        assert_eq!(cpk.0.len(), 16 + 10944);
    }

    fn test_expand_sk_for_variant(params_enum: &MayoParams) {
        let params_variant = params_enum.variant();
        let (csk, _cpk) = compact_key_gen(params_enum).expect("Compact keygen failed");

        let esk_res = expand_sk(&csk, params_enum);
        assert!(esk_res.is_ok(), "expand_sk failed: {:?}", esk_res.err());
        let esk = esk_res.unwrap();

        assert!(!esk.0.is_empty(), "Expanded secret key should not be empty");

        // Verify starting part of esk is csk
        assert_eq!(&esk.0[0..params_variant.sk_seed_bytes], &csk.0[..],
                   "ESK does not start with CSK");

        // Verify O_bytes part
        let o_bytes_start = params_variant.sk_seed_bytes;
        let o_bytes_end = o_bytes_start + params_variant.o_bytes;
        let esk_o_bytes = &esk.0[o_bytes_start..o_bytes_end];
        
        // Re-derive o_bytes for comparison (as done in expand_sk)
        let seedsk_for_check = SeedSK(csk.0.clone());
        let (_seedpk_for_check, o_bytes_derived) = shake256_xof_derive_pk_seed_and_o(&seedsk_for_check, params_enum);
        assert_eq!(esk_o_bytes, &o_bytes_derived[..], "ESK o_bytes part mismatch");

        // Verify P1_all_bytes part
        let p1_bytes_start = o_bytes_end;
        let p1_bytes_end = p1_bytes_start + params_variant.p1_bytes;
        let esk_p1_bytes = &esk.0[p1_bytes_start..p1_bytes_end];

        // Re-derive p1_all_bytes for comparison
        let p1_all_bytes_derived = derive_p1_bytes(&_seedpk_for_check, params_variant);
        assert_eq!(esk_p1_bytes, &p1_all_bytes_derived[..], "ESK p1_bytes part mismatch");
        
        // Verify L_all_bytes length
        let l_bytes_start = p1_bytes_end;
        let num_l_elements = params_variant.m * (params_variant.n - params_variant.o) * (params_variant.n - params_variant.o);
        let expected_l_bytes_len = MayoParams::bytes_for_gf16_elements(num_l_elements);
        assert_eq!(esk.0.len(), params_variant.sk_seed_bytes + params_variant.o_bytes + params_variant.p1_bytes + expected_l_bytes_len,
                   "Total ESK length mismatch");
        let esk_l_bytes = &esk.0[l_bytes_start..];
        assert_eq!(esk_l_bytes.len(), expected_l_bytes_len, "ESK l_bytes part length mismatch");
    }

    #[test]
    fn test_expand_sk_mayo1() {
        test_expand_sk_for_variant(&MayoParams::mayo1());
    }

    #[test]
    fn test_expand_sk_mayo2() {
        test_expand_sk_for_variant(&MayoParams::mayo2());
    }

    fn test_expand_pk_for_variant(params_enum: &MayoParams) {
        let params_variant = params_enum.variant();
        let (_csk, cpk) = compact_key_gen(params_enum).expect("Compact keygen failed");

        let epk_res = expand_pk(&cpk, params_enum);
        assert!(epk_res.is_ok(), "expand_pk failed: {:?}", epk_res.err());
        let epk = epk_res.unwrap();

        assert!(!epk.0.is_empty(), "Expanded public key should not be empty");
        
        let expected_total_len = params_variant.p1_bytes + params_variant.p2_bytes + params_variant.p3_bytes;
        assert_eq!(epk.0.len(), expected_total_len, "EPK total length mismatch");

        // Verify components of epk.0
        // Re-derive P1_all_bytes and P2_all_bytes from seedpk part of cpk
        let seedpk_bytes_from_cpk = &cpk.0[0..params_variant.pk_seed_bytes];
        let seedpk_for_check = SeedPK(seedpk_bytes_from_cpk.to_vec());
        
        let p1_all_bytes_derived = derive_p1_bytes(&seedpk_for_check, params_variant);
        let p2_all_bytes_derived = derive_p2_bytes(&seedpk_for_check, params_variant);
        let p3_all_bytes_from_cpk = &cpk.0[params_variant.pk_seed_bytes..];

        assert_eq!(&epk.0[0..params_variant.p1_bytes], &p1_all_bytes_derived[..],
                   "EPK p1_bytes part mismatch");
        
        let p2_start = params_variant.p1_bytes;
        let p2_end = p2_start + params_variant.p2_bytes;
        assert_eq!(&epk.0[p2_start..p2_end], &p2_all_bytes_derived[..],
                   "EPK p2_bytes part mismatch");

        let p3_start = p2_end;
        assert_eq!(&epk.0[p3_start..], p3_all_bytes_from_cpk,
                   "EPK p3_bytes part mismatch");
    }

    #[test]
    fn test_expand_pk_mayo1() {
        test_expand_pk_for_variant(&MayoParams::mayo1());
    }

    #[test]
    fn test_expand_pk_mayo2() {
        test_expand_pk_for_variant(&MayoParams::mayo2());
    }
}
