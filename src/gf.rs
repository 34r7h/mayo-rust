//! Implements arithmetic for the finite field GF(16).
//! The field is defined by the irreducible polynomial x^4 + x + 1 (0x13 or 0b10011).

use crate::types::GFElement;
use crate::params::F_POLY_U8; // Using the u8 version: 0b0001_0011

// Mask to ensure we only operate on the lower 4 bits (nibble)
const NIBBLE_MASK: u8 = 0x0F;

/// Adds two GF(16) elements.
/// In GF(2^n), addition is XOR. Result is masked to 4 bits.
#[inline]
pub fn gf16_add(a: GFElement, b: GFElement) -> GFElement {
    GFElement((a.0 ^ b.0) & NIBBLE_MASK)
}

/// Subtracts one GF(16) element from another.
/// In GF(2^n), subtraction is the same as addition (XOR). Result is masked to 4 bits.
#[inline]
pub fn gf16_sub(a: GFElement, b: GFElement) -> GFElement {
    GFElement((a.0 ^ b.0) & NIBBLE_MASK) // Identical to add
}

/// Multiplies two GF(16) elements using bitwise operations (Russian peasant method variant).
/// Field is GF(2^4) with irreducible polynomial x^4 + x + 1 (F_POLY_U8 = 0b00010011).
pub fn gf16_mul(a: GFElement, b: GFElement) -> GFElement {
    let mut p: u8 = 0; // Accumulator for the product
    let mut val_a = a.0 & NIBBLE_MASK;
    let mut val_b = b.0 & NIBBLE_MASK;

    // Russian peasant multiplication adapted for GF(2^n)
    for _ in 0..4 { // Iterate 4 times for 4 bits of b
        if (val_b & 1) != 0 { // If LSB of b is 1
            p ^= val_a;      // Add (XOR) a to product
        }
        
        val_b >>= 1; // Shift b to the right (divide by 2)
        
        // Check if a needs reduction before next XOR with p
        // (This is actually about shifting 'a' and reducing it if it overflows)
        let high_bit_set = (val_a & 0x08) != 0; // Check if 4th bit of a (val_a_3) is set
        val_a <<= 1; // Shift a to the left (multiply by x)
        
        if high_bit_set {
            val_a ^= F_POLY_U8; // Reduce by XORing with the irreducible polynomial
        }
        val_a &= NIBBLE_MASK; // Ensure val_a stays within 4 bits after potential reduction
                              // This mask is important if F_POLY_U8 itself has bits beyond the 4th if not careful
                              // For F_POLY_U8 = 0b00010011, it correctly reduces x^4 to x+1.
                              // Example: if val_a was 0b1000 (x^3), it becomes 0b10000 (x^4).
                              // Then 0b10000 ^ 0b10011 = 0b0011 (x+1).
                              // The NIBBLE_MASK here is mostly for safety ensuring intermediate val_a doesn't grow.
                              // The actual reduction is what keeps it in the field.
    }
    GFElement(p & NIBBLE_MASK)
}

/// Computes base^exp in GF(16).
pub fn gf16_pow(base: GFElement, exp: usize) -> GFElement {
    if exp == 0 {
        return GFElement(1); // g^0 = 1
    }
    let mut result = base;
    for _ in 1..exp {
        result = gf16_mul(result, base);
    }
    result
}


#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create GFElement from u8 for tests
    fn gf(val: u8) -> GFElement {
        GFElement(val)
    }

    #[test]
    fn test_gf16_add_sub() {
        assert_eq!(gf16_add(gf(0x5), gf(0x9)).0, 0xC); // 0101 ^ 1001 = 1100
        assert_eq!(gf16_add(gf(0xA), gf(0xA)).0, 0x0); // a + a = 0
        assert_eq!(gf16_add(gf(0x3), gf(0x0)).0, 0x3); // a + 0 = a

        // Subtraction is same as addition
        assert_eq!(gf16_sub(gf(0xC), gf(0x9)).0, 0x5); 
        assert_eq!(gf16_sub(gf(0xA), gf(0xA)).0, 0x0);
        assert_eq!(gf16_sub(gf(0x3), gf(0x0)).0, 0x3);
    }

    #[test]
    fn test_gf16_mul_by_zero_and_one() {
        assert_eq!(gf16_mul(gf(0x0), gf(0x5)).0, 0x0);
        assert_eq!(gf16_mul(gf(0x5), gf(0x0)).0, 0x0);
        assert_eq!(gf16_mul(gf(0x1), gf(0x5)).0, 0x5);
        assert_eq!(gf16_mul(gf(0x5), gf(0x1)).0, 0x5);
        assert_eq!(gf16_mul(gf(0xF), gf(0x1)).0, 0xF);
    }

    #[test]
    fn test_gf16_mul_known_products() {
        // Irreducible polynomial: x^4 + x + 1 (0x13)
        // Let's test powers of x (element 0x2)
        // x = 0x2
        // x^2 = 0x4
        // x^3 = 0x8
        // x^4 = x + 1 = 0x2 ^ 0x1 = 0x3
        // x^5 = x(x+1) = x^2+x = 0x4 ^ 0x2 = 0x6
        // x^6 = x(x^2+x) = x^3+x^2 = 0x8 ^ 0x4 = 0xC
        // x^7 = x(x^3+x^2) = x^4+x^3 = (x+1)+x^3 = 0x3 ^ 0x8 = 0xB
        // x^8 = x((x+1)+x^3) = x^2+x+x^4 = x^2+x+(x+1) = x^2 = 0x4. This is wrong.
        // Let's re-verify x^4 reduction:
        // if a = 0b1000 (x^3), b = 0b0010 (x)
        // p=0, a=8, b=2
        // b&1=0
        // b=1, a=0b10000 -> a^=0b10011 -> a=0b0011 (3)
        // b&1=1, p=p^a = 0^3 = 3
        // b=0, a=0b0110 (6)
        // result p=3. So x^3 * x = x^4 = 3. Correct.
        
        assert_eq!(gf16_mul(gf(0x2), gf(0x1)).0, 0x2); // x * 1 = x
        assert_eq!(gf16_mul(gf(0x2), gf(0x2)).0, 0x4); // x * x = x^2
        assert_eq!(gf16_mul(gf(0x4), gf(0x2)).0, 0x8); // x^2 * x = x^3
        assert_eq!(gf16_mul(gf(0x8), gf(0x2)).0, 0x3); // x^3 * x = x^4 = x+1 (0b0011)
        assert_eq!(gf16_mul(gf(0x3), gf(0x2)).0, 0x6); // (x+1)*x = x^2+x (0b0110)
        assert_eq!(gf16_mul(gf(0x6), gf(0x2)).0, 0xC); // (x^2+x)*x = x^3+x^2 (0b1100)
        assert_eq!(gf16_mul(gf(0xC), gf(0x2)).0, 0xB); // (x^3+x^2)*x = x^4+x^3 = (x+1)+x^3 (0b1011)
        assert_eq!(gf16_mul(gf(0xB), gf(0x2)).0, 0x5); // (x^3+x+1)*x = x^4+x^2+x = (x+1)+x^2+x = x^2+1 (0b0101)

        // Test some other values
        // 0x5 * 0x7 = (x^2+1)(x^2+x+1) = x^4+x^3+x^2 + x^2+x+1 = (x+1)+x^3+x = x^3+1 = 0x8^0x1 = 0x8
        assert_eq!(gf16_mul(gf(0x5), gf(0x7)).0, 0x8);
        // 0xA * 0xB = (x^3+x^2)(x^3+x+1) = x^6+x^4+x^3 + x^5+x^3+x^2 = x^6+x^5+x^4+x^2
        // x^6 = 0xC (x^3+x^2)
        // x^5 = 0x6 (x^2+x)
        // x^4 = 0x3 (x+1)
        // x^2 = 0x4 (x^2)
        // 0xC ^ 0x6 ^ 0x3 ^ 0x4 = (1100^0110 = 1010) ^ (0011^0100 = 0111) = 1010^0111 = 1101 = 0xD
        assert_eq!(gf16_mul(gf(0xA), gf(0xB)).0, 0x2);
    }

    #[test]
    fn test_gf16_mul_commutativity() {
        for i in 0..16 {
            for j in 0..16 {
                assert_eq!(gf16_mul(gf(i), gf(j)).0, gf16_mul(gf(j), gf(i)).0, "Failed for i={}, j={}", i, j);
            }
        }
    }
    
    #[test]
    fn test_gf16_mul_associativity() {
        // Test a few triplets
        let triplets = [(gf(0x2), gf(0x3), gf(0x4)), (gf(0x5), gf(0x6), gf(0x7)), (gf(0x8), gf(0x9), gf(0xA))];
        for (a,b,c) in triplets.iter() {
            let ab_c = gf16_mul(gf16_mul(*a, *b), *c);
            let a_bc = gf16_mul(*a, gf16_mul(*b, *c));
            assert_eq!(ab_c.0, a_bc.0, "Associativity failed for ({:?}, {:?}, {:?})", a,b,c);
        }
    }

    #[test]
    fn test_gf16_mul_distributivity() {
        // Test a few triplets
        let triplets = [(gf(0x2), gf(0x3), gf(0x4)), (gf(0x5), gf(0x6), gf(0x7)), (gf(0x8), gf(0x9), gf(0xA))];
        for (a,b,c) in triplets.iter() {
            let a_b_plus_c = gf16_mul(*a, gf16_add(*b, *c));
            let ab_plus_ac = gf16_add(gf16_mul(*a, *b), gf16_mul(*a, *c));
            assert_eq!(a_b_plus_c.0, ab_plus_ac.0, "Distributivity failed for ({:?}, {:?}, {:?})", a,b,c);
        }
    }
    
    #[test]
    fn test_gf16_pow() {
        // x = 0x2
        assert_eq!(gf16_pow(gf(0x2), 0).0, 0x1); // x^0 = 1
        assert_eq!(gf16_pow(gf(0x2), 1).0, 0x2); // x^1 = x
        assert_eq!(gf16_pow(gf(0x2), 2).0, 0x4); // x^2
        assert_eq!(gf16_pow(gf(0x2), 3).0, 0x8); // x^3
        assert_eq!(gf16_pow(gf(0x2), 4).0, 0x3); // x^4 = x+1
        assert_eq!(gf16_pow(gf(0x2), 5).0, 0x6); // x^5 = x^2+x
        assert_eq!(gf16_pow(gf(0x2), 14).0, gf16_mul(gf16_pow(gf(0x2),7), gf16_pow(gf(0x2),7)).0 ); // x^14
        assert_eq!(gf16_pow(gf(0x2), 15).0, 0x1); // x^15 = 1 (since GF(16)* is cyclic group of order 15)

        // Test with another base
        assert_eq!(gf16_pow(gf(0x5), 0).0, 0x1);
        assert_eq!(gf16_pow(gf(0x5), 1).0, 0x5);
        assert_eq!(gf16_pow(gf(0x5), 2).0, gf16_mul(gf(0x5), gf(0x5)).0); // 5*5 = (x^2+1)(x^2+1) = x^4+1 = (x+1)+1 = x = 0x2
        assert_eq!(gf16_pow(gf(0x5), 2).0, 0x2); 
        assert_eq!(gf16_pow(gf(0x5), 3).0, gf16_mul(gf(0x2), gf(0x5)).0); // 0x2 * 0x5 = x(x^2+1) = x^3+x = 0x8^0x2 = 0xA
        assert_eq!(gf16_pow(gf(0x5), 3).0, 0xA);
    }
}
