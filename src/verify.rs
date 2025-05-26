//! Implements MAYO.Verify (Algorithm 9).

use crate::types::{ExpandedPublicKey, Message, Signature, GFVector, Salt, GFMatrix}; // Removed MessageDigest, GFElement
use crate::params::{MayoParams, MayoVariantParams};
use crate::hash::{shake256_digest, shake256_derive_target_t};
use crate::codec::{decode_p1_matrices, decode_p2_matrices, decode_p3_matrices, decode_s_vector, decode_gf_elements};
use crate::matrix::{matrix_symmetrize, matrix_vec_mul_transpose_gfvector, vector_dot_product};
use crate::gf::gf16_add;

/// Computes the public map P*(s) for MAYO verification.
///
/// # Arguments
/// * `s_vector` - The solution vector from the signature (n elements).
/// * `p1_matrices` - The set of m P1_i matrices from epk, each (n-o)x(n-o) upper triangular.
/// * `p2_matrices` - The set of m P2_i matrices from epk, each (n-o)xo.
/// * `p3_matrices` - The set of m P3_i matrices from epk, each oxo upper triangular.
/// * `params` - MAYO variant parameters.
///
/// # Returns
/// `Ok(GFVector /* y_vector, m elements */)` or an error string.
fn compute_p_star_s(
    s_vector: &GFVector,
    p1_matrices: &[GFMatrix],
    p2_matrices: &[GFMatrix],
    p3_matrices: &[GFMatrix],
    params: &MayoVariantParams
) -> Result<GFVector /* y_vector */, &'static str> {
    if s_vector.len() != params.n {
        return Err("Signature vector s has incorrect length");
    }
    if p1_matrices.len() != params.m || p2_matrices.len() != params.m || p3_matrices.len() != params.m {
        return Err("Incorrect number of P matrices");
    }

    let num_vinegar_vars = params.n - params.o;
    let num_oil_vars = params.o;

    // Check consistency of s_vector length with n-o and o
    if num_vinegar_vars + num_oil_vars != params.n {
        return Err("Internal error: n-o + o != n");
    }

    let s_v = &s_vector[0..num_vinegar_vars];
    let s_o = &s_vector[num_vinegar_vars..params.n];
    
    let s_v_gfvec = s_v.to_vec(); 
    let s_o_gfvec = s_o.to_vec();

    let mut y_elements: GFVector = Vec::with_capacity(params.m);

    for i in 0..params.m {
        let p1_i = &p1_matrices[i];
        let p2_i = &p2_matrices[i];
        let p3_i = &p3_matrices[i];

        // Dimension checks for each matrix P_i^k
        if p1_i.num_rows() != num_vinegar_vars || p1_i.num_cols() != num_vinegar_vars {
            return Err("P1 matrix dimension mismatch");
        }
        if p2_i.num_rows() != num_vinegar_vars || p2_i.num_cols() != num_oil_vars {
            return Err("P2 matrix dimension mismatch");
        }
        if p3_i.num_rows() != num_oil_vars || p3_i.num_cols() != num_oil_vars {
            return Err("P3 matrix dimension mismatch");
        }

        // Symmetrize P1_i and P3_i (M + M^T, diagonal becomes 0)
        let p1_i_sym = matrix_symmetrize(p1_i)?;
        let p3_i_sym = matrix_symmetrize(p3_i)?;

        // Term 1: s_V^T * P1_i_sym * s_V
        let sv_p1_intermediate = matrix_vec_mul_transpose_gfvector(&s_v_gfvec, &p1_i_sym)?;
        let term1 = vector_dot_product(&sv_p1_intermediate, &s_v_gfvec)?;

        // Term 2: s_V^T * P2_i * s_O
        let sv_p2_intermediate = matrix_vec_mul_transpose_gfvector(&s_v_gfvec, p2_i)?;
        let term2 = vector_dot_product(&sv_p2_intermediate, &s_o_gfvec)?;

        // Term 3: s_O^T * P3_i_sym * s_O
        let so_p3_intermediate = matrix_vec_mul_transpose_gfvector(&s_o_gfvec, &p3_i_sym)?;
        let term3 = vector_dot_product(&so_p3_intermediate, &s_o_gfvec)?;
        
        let y_i = gf16_add(gf16_add(term1, term2), term3);
        y_elements.push(y_i);
    }
    Ok(y_elements)
}

/// Implements MAYO.Verify (Algorithm 9 from the MAYO specification).
/// Verifies a signature against a message and an expanded public key.
pub fn verify_signature(epk: &ExpandedPublicKey, message: &Message, signature: &Signature, params_enum: &MayoParams) -> Result<bool, &'static str> {
    let params = params_enum.variant();

    // 1. Decode epk into P1, P2, P3 matrices
    let p1_bytes_end = params.p1_bytes;
    let p2_bytes_end = params.p1_bytes + params.p2_bytes;

    if epk.0.len() != params.p1_bytes + params.p2_bytes + params.p3_bytes {
        return Err("Expanded public key has incorrect length");
    }

    let p1_all_bytes = &epk.0[0..p1_bytes_end];
    let p2_all_bytes = &epk.0[p1_bytes_end..p2_bytes_end];
    let p3_all_bytes = &epk.0[p2_bytes_end..];

    let p1_matrices = decode_p1_matrices(p1_all_bytes, params)?;
    let p2_matrices = decode_p2_matrices(p2_all_bytes, params)?;
    let p3_matrices = decode_p3_matrices(p3_all_bytes, params)?;

    // 2. Decode signature into salt and s_vector
    let s_bytes_len = MayoParams::bytes_for_gf16_elements(params.n);
    if signature.0.len() != s_bytes_len + params.salt_bytes {
        return Err("Signature has incorrect length");
    }
    let s_bytes = &signature.0[0..s_bytes_len];
    let salt_bytes_slice = &signature.0[s_bytes_len..];
    
    let s_vector = decode_s_vector(s_bytes, params)?;
    let salt = Salt(salt_bytes_slice.to_vec());

    // 3. Hash message M to M_digest
    let m_digest = shake256_digest(&message.0, params_enum);

    // 4. Derive target vector t
    let t_bytes = shake256_derive_target_t(&m_digest, &salt, params_enum);
    let t_vector = decode_gf_elements(&t_bytes, params.m)?;

    // 5. Compute y = P*(s)
    let y_computed_vector = compute_p_star_s(&s_vector, &p1_matrices, &p2_matrices, &p3_matrices, params)?;
    
    if y_computed_vector.len() != params.m {
        // This check should be redundant if compute_p_star_s is correct
        return Err("Computed y vector has incorrect length");
    }

    // 6. Compare computed y with target t
    Ok(y_computed_vector == t_vector)
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::MayoParams;
    // GFElement removed from here as it's only used in create_dummy_signature for GFElement(0) which can be Self(0) or just 0 if type inference works.
    // However, GFVector is Vec<GFElement>, so GFElement itself might still be needed if GFVector is constructed with GFElement explicitly.
    // Let's check if the compiler complains after removing GFElement from the main import. It's used in dummy_s_vector.
    use crate::types::{ExpandedPublicKey as EpkTypeForTest, Signature as SigTypeForTest, Message as MsgTypeForTest, GFElement}; // Re-added GFElement for test
    use crate::keygen::{compact_key_gen, expand_pk}; 
    use crate::codec::encode_s_vector; 

    fn create_dummy_epk(params_enum: &MayoParams) -> EpkTypeForTest {
        let (_csk, cpk) = compact_key_gen(params_enum).unwrap();
        expand_pk(&cpk, params_enum).unwrap()
    }

    fn create_dummy_signature(params_enum: &MayoParams) -> SigTypeForTest {
        let params = params_enum.variant();
        let s_len = params.n;
        let s_bytes_len = MayoParams::bytes_for_gf16_elements(s_len);
        let salt_len = params.salt_bytes;

        let dummy_s_vector: GFVector = vec![GFElement(0); s_len];
        let s_bytes = encode_s_vector(&dummy_s_vector, params);
        
        let dummy_salt_bytes = vec![0u8; salt_len];
        
        let mut sig_bytes = Vec::with_capacity(s_bytes_len + salt_len);
        sig_bytes.extend_from_slice(&s_bytes);
        sig_bytes.extend_from_slice(&dummy_salt_bytes);
        
        SigTypeForTest(sig_bytes)
    }

    #[test]
    fn test_verify_signature_flow_mayo1() {
        let params_enum = MayoParams::mayo1();
        let epk = create_dummy_epk(&params_enum);
        let message = MsgTypeForTest(b"test message for verify".to_vec());
        let signature = create_dummy_signature(&params_enum);

        let verify_result = verify_signature(&epk, &message, &signature, &params_enum);
        
        // With compute_p_star_s implemented, we expect Ok(false) for a dummy signature
        // as it's highly unlikely to match the recomputed t_vector.
        match verify_result {
            Ok(false) => { /* Expected for a dummy signature not matching a real message hash */ }
            Ok(true) => panic!("Verification unexpectedly succeeded with a dummy signature"),
            Err(e) => panic!("Verification failed with an unexpected error: {}", e),
        }
    }

    #[test]
    fn test_verify_signature_flow_mayo2() {
        let params_enum = MayoParams::mayo2();
        let epk = create_dummy_epk(&params_enum);
        let message = MsgTypeForTest(b"another test message for verify".to_vec());
        let signature = create_dummy_signature(&params_enum);

        let verify_result = verify_signature(&epk, &message, &signature, &params_enum);
        match verify_result {
            Ok(false) => { /* Expected for a dummy signature */ }
            Ok(true) => panic!("Verification unexpectedly succeeded with a dummy signature"),
            Err(e) => panic!("Verification failed with an unexpected error: {}", e),
        }
    }

    #[test]
    fn test_verify_signature_length_checks() {
        let params_enum = MayoParams::mayo1();
        let epk = create_dummy_epk(&params_enum);
        let message = MsgTypeForTest(b"test".to_vec());
        let valid_signature = create_dummy_signature(&params_enum);

        let mut wrong_epk_bytes = epk.0.clone();
        wrong_epk_bytes.pop();
        let wrong_epk = EpkTypeForTest(wrong_epk_bytes);
        assert_eq!(verify_signature(&wrong_epk, &message, &valid_signature, &params_enum), 
                   Err("Expanded public key has incorrect length"));

        let mut wrong_sig_bytes = valid_signature.0.clone();
        wrong_sig_bytes.pop();
        let wrong_sig = SigTypeForTest(wrong_sig_bytes);
        assert_eq!(verify_signature(&epk, &message, &wrong_sig, &params_enum),
                   Err("Signature has incorrect length"));
    }
    
    // TODO: More detailed structural tests once compute_p_star_s is implemented.
    // These tests would involve:
    // 1. Mocking or providing a test implementation for compute_p_star_s.
    // 2. Scenario 1: Test verification success:
    //    - Have compute_p_star_s return a y_computed_vector that matches the t_vector derived in the test.
    //    - Assert that verify_signature returns Ok(true).
    // 3. Scenario 2: Test verification failure (y_computed mismatch):
    //    - Have compute_p_star_s return a y_computed_vector that *does not* match the t_vector.
    //    - Assert that verify_signature returns Ok(false).
    // These tests verify the comparison logic in verify_signature.

    // TODO: Implement Known Answer Tests (KATs) for verify_signature 
    // once compute_p_star_s is fully implemented.
    // These tests will use official MAYO test vectors.
}
