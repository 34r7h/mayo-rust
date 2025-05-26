use wasm_bindgen::prelude::*;
// use crate::params::MayoParams; // Removed as per compiler warning

// Field element for GF(16), represented as a nibble in a u8.
// The actual value should be in the lower 4 bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GFElement(pub u8);

// Vector of field elements.
pub type GFVector = Vec<GFElement>;

// Matrix of field elements (row-major storage).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GFMatrix {
    pub data: Vec<GFElement>,
    pub rows: usize,
    pub cols: usize,
}

impl GFMatrix {
    pub fn new(rows: usize, cols: usize) -> Self {
        Self {
            data: vec![GFElement::default(); rows * cols],
            rows,
            cols,
        }
    }

    // Helper to get element (row, col)
    pub fn get(&self, r: usize, c: usize) -> Option<&GFElement> {
        if r < self.rows && c < self.cols {
            self.data.get(r * self.cols + c)
        } else {
            None
        }
    }

    // Helper to set element (row, col)
    pub fn set(&mut self, r: usize, c: usize, val: GFElement) {
        if r < self.rows && c < self.cols {
            self.data[r * self.cols + c] = val;
        }
    }
}


// Cryptographic types - currently Vec<u8> wrappers.
// TODO: Once MayoParams are finalized, these could become fixed-size arrays [u8; N]
// or structs that enforce byte length constraints based on MayoParams.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedSK(pub Vec<u8>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedPK(pub Vec<u8>);

/// CompactSecretKey is typically the same as SeedSK.
#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Clone, PartialEq, Eq)] // Removed Copy
pub struct CompactSecretKey(pub Vec<u8>); // Represents SeedSK

#[wasm_bindgen]
impl CompactSecretKey {
    #[wasm_bindgen(constructor)]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn get_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}

/// CompactPublicKey typically contains SeedPK and a representation of P3 (or its hash).
#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Clone, PartialEq, Eq)] // Removed Copy
pub struct CompactPublicKey(pub Vec<u8>); // Represents SeedPK || P3_bytes or similar

#[wasm_bindgen]
impl CompactPublicKey {
    #[wasm_bindgen(constructor)]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn get_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}

/// ExpandedSecretKey contains the full secret key components derived from SeedSK.
/// This would include S, P1, P2, P3 (or their components).
#[derive(Debug, Clone, PartialEq, Eq)] // Ensure no Copy
pub struct ExpandedSecretKey(pub Vec<u8>);

/// ExpandedPublicKey contains the full public key components derived from SeedPK.
/// This would include P1, P2, P3 (or parts of them, or their public representation).
#[derive(Debug, Clone, PartialEq, Eq)] // Ensure no Copy
pub struct ExpandedPublicKey(pub Vec<u8>);

/// Signature containing the solution `s` and the salt.
#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Clone, PartialEq, Eq)] // Removed Copy
pub struct Signature(pub Vec<u8>); // Represents s_bytes || salt

#[wasm_bindgen]
impl Signature {
    #[wasm_bindgen(constructor)]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn get_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}

#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Clone, PartialEq, Eq)] // Removed Copy
pub struct Message(pub Vec<u8>);

#[wasm_bindgen]
impl Message {
    #[wasm_bindgen(constructor)]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn get_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageDigest(pub Vec<u8>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Salt(pub Vec<u8>);

// Implementations for converting to/from bytes for these types might be useful later.
// e.g., impl From<Vec<u8>> for SeedSK ...
// impl AsRef<[u8]> for SeedSK ...
