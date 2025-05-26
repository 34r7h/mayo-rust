//! Defines parameters for different MAYO security levels.

/// Irreducible polynomial for GF(16): x^4 + x + 1
/// (coefficients in little-endian for degree, e.g., 0b...c3 c2 c1 c0)
/// x^4 + x + 1 is 1*x^4 + 0*x^3 + 0*x^2 + 1*x^1 + 1*x^0 -> 10011
pub const F_POLY_U8: u8 = 0b0001_0011; // As u8, used in some contexts if operations are byte-wise
pub const F_POLY_U16: u16 = 0x13;     // As u16, matching the subtask description (0x13 = 19 = 0b10011)

/// Holds the specific parameters for a MAYO variant (e.g., MAYO1, MAYO2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MayoVariantParams {
    // Core MQ parameters
    pub n: usize, // Number of variables (elements in a solution vector s)
    pub m: usize, // Number of equations in P (elements in t)
    pub o: usize, // Number of vinegar variables
    pub k: usize, // Number of solutions to find / oil variables used in G
    
    // Byte lengths for seeds, salts, digests
    pub sk_seed_bytes: usize,   // Security parameter lambda
    pub pk_seed_bytes: usize,   // For PK seed (Note: AES key size for P1/P2 derivation)
    pub salt_bytes: usize,      // For salt in signature
    pub digest_bytes: usize,    // For message digest (e.g., SHAKE256 output length)

    // Byte lengths for various components derived from seeds or used in the scheme
    pub o_bytes: usize,         // Serialized oil variables component (e.g., G or its seed)
    pub p1_bytes: usize,        // Serialized P1 matrix component (derived via AES-CTR from pk_seed)
    pub p2_bytes: usize,        // Serialized P2 matrix component (derived via AES-CTR from pk_seed)
    pub p3_bytes: usize,        // Serialized P3 matrix component (derived via SHAKE from pk_seed)
    
    // TODO: Add any other derived byte lengths if useful, e.g., bytes for csk, cpk, esk, epk, sig.
    // These would be calculated based on n, m, o, k, and q (field_elements_to_bytes).
    // For example:
    // csk_bytes: sk_seed_bytes
    // cpk_bytes: pk_seed_bytes + bytes_for_gf16_elements(m * (n-o)*(n-o+1)/2) for P3, or its hash.
    // sig_bytes: salt_bytes + bytes_for_gf16_elements(n) for solution s.
}

/// Enum to select a specific set of MAYO parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MayoParams {
    MAYO1(MayoVariantParams),
    MAYO2(MayoVariantParams),
    // Potentially MAYO3, MAYO5 in the future
}

impl MayoParams {
    /// Field characteristic (GF(2^4) means q=16).
    pub const Q: usize = 16;
    // F_POLY is defined as a top-level constant in this file (F_POLY_U16 or F_POLY_U8).

    /// Parameters for MAYO1 (NIST Level 1 equivalent).
    pub fn mayo1() -> Self {
        MayoParams::MAYO1(MayoVariantParams {
            n: 66, m: 64, o: 8, k: 9,
            sk_seed_bytes: 24,  // Corresponds to NIST's rho parameter for MAYO1
            pk_seed_bytes: 16,  // AES-128 key size
            salt_bytes: 24,     // Corresponds to NIST's salt parameter for MAYO1
            digest_bytes: 32,   // For a 256-bit digest (e.g. SHAKE256/256)
            o_bytes: 232,       // From MAYO spec, Table 1 (G_bytes for MAYO1_PK)
            p1_bytes: 54784,    // 64 * 856 (calculated for 58x58 upper triangular)
            p2_bytes: 14848,    // 64 * 232 (calculated for 58x8)
            p3_bytes: 1152,     // 64 * 18 (calculated for 8x8 upper triangular)
        })
    }

    /// Parameters for MAYO2 (NIST Level 3 equivalent, if mapping directly).
    /// Note: The parameters provided (n=78, m=64, o=18, k=4) align with "mayo_2" from some reference implementations.
    /// These values are also consistent with NIST Level 3 parameters for MAYO.
    pub fn mayo2() -> Self {
        MayoParams::MAYO2(MayoVariantParams {
            n: 78, m: 64, o: 18, k: 4,
            sk_seed_bytes: 24,  // Corresponds to NIST's rho parameter for MAYO2 (assuming it's MAYO-L3 mapping)
            pk_seed_bytes: 16,  // AES-128 key size
            salt_bytes: 24,     // Corresponds to NIST's salt parameter for MAYO2
            digest_bytes: 32,   // For a 256-bit digest
            o_bytes: 540,       // From MAYO spec, Table 1 (G_bytes for MAYO2_PK)
            p1_bytes: 58560,   // 64 * 1830 (calculated for 60x60 upper triangular)
            p2_bytes: 34560,    // 64 * 360 (calculated for 60x18)
            p3_bytes: 5504,    // 64 * 171 (calculated for 18x18 upper triangular)
        })
    }

    /// Accessor method to get the underlying `MayoVariantParams`.
    pub fn variant(&self) -> &MayoVariantParams {
        match self {
            MayoParams::MAYO1(p) => p,
            MayoParams::MAYO2(p) => p,
        }
    }

    /// Helper method to calculate bytes needed to store a given number of GF(16) elements.
    /// Each GF(16) element is 4 bits (a nibble).
    pub fn bytes_for_gf16_elements(num_elements: usize) -> usize {
        (num_elements + 1) / 2
    }

    // Convenience accessors delegated to the variant
    pub fn n(&self) -> usize { self.variant().n }
    pub fn m(&self) -> usize { self.variant().m }
    pub fn o(&self) -> usize { self.variant().o }
    pub fn k(&self) -> usize { self.variant().k }
    pub fn sk_seed_bytes(&self) -> usize { self.variant().sk_seed_bytes }
    pub fn pk_seed_bytes(&self) -> usize { self.variant().pk_seed_bytes }
    pub fn salt_bytes(&self) -> usize { self.variant().salt_bytes }
    pub fn digest_bytes(&self) -> usize { self.variant().digest_bytes }
    pub fn o_bytes(&self) -> usize { self.variant().o_bytes }
    pub fn p1_bytes(&self) -> usize { self.variant().p1_bytes }
    pub fn p2_bytes(&self) -> usize { self.variant().p2_bytes }
    pub fn p3_bytes(&self) -> usize { self.variant().p3_bytes }

    pub fn get_params_by_name(name: &str) -> Result<MayoParams, String> {
        match name.to_lowercase().as_str() {
            "mayo1" => Ok(MayoParams::mayo1()),
            "mayo2" => Ok(MayoParams::mayo2()),
            // Add other variants if they exist in the future
            _ => Err(format!("Unknown MAYO variant name: {}", name)),
        }
    }
}

// Example usage:
// let params_mayo1 = MayoParams::mayo1();
// let n_val = params_mayo1.n();
// let specific_variant_params = params_mayo1.variant();
// let p1_bytes_val = specific_variant_params.p1_bytes;
// or directly:
// let p1_bytes_val_direct = params_mayo1.p1_bytes();
