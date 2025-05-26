// mayo-zig/src/gf.zig

//! Implements arithmetic for the finite field GF(16).
//! The field is defined by the irreducible polynomial x^4 + x + 1 (0x13 or 0b10011).

const std = @import("std");
const types = @import("types.zig");
const params = @import("params.zig");

const GFElement = types.GFElement;

// Mask to ensure we only operate on the lower 4 bits (nibble)
// GFElement.val is already u4, so direct use is fine. Masking might be useful if operating on u8 representations.
// const NIBBLE_MASK: u8 = 0x0F; // Not strictly needed if using GFElement.val: u4

/// Adds two GF(16) elements.
/// In GF(2^n), addition is XOR.
pub fn gf16_add(a: GFElement, b: GFElement) GFElement {
    return GFElement.new(a.value() ^ b.value());
}

/// Subtracts one GF(16) element from another.
/// In GF(2^n), subtraction is the same as addition (XOR).
pub fn gf16_sub(a: GFElement, b: GFElement) GFElement {
    return GFElement.new(a.value() ^ b.value()); // Identical to add
}

/// Multiplies two GF(16) elements using bitwise operations (Russian peasant method variant).
/// Field is GF(2^4) with irreducible polynomial x^4 + x + 1 (params.F_POLY_U8 = 0b00010011).
pub fn gf16_mul(a: GFElement, b: GFElement) GFElement {
    var p: u8 = 0; // Accumulator for the product
    var val_a = a.value();
    var val_b = b.value();

    // Russian peasant multiplication adapted for GF(2^n)
    var i: u3 = 0; // Iterate 4 times for 4 bits of b
    while (i < 4) : (i += 1) {
        if ((val_b & 1) != 0) { // If LSB of b is 1
            p ^= val_a; // Add (XOR) a to product
        }
        
        val_b >>= 1; // Shift b to the right (divide by 2)
        
        const high_bit_set = (val_a & 0x08) != 0; // Check if 4th bit of a (val_a_3) is set
        val_a <<= 1; // Shift a to the left (multiply by x)
        
        if (high_bit_set) {
            val_a ^= params.F_POLY_U8; // Reduce by XORing with the irreducible polynomial
        }
        // val_a &= NIBBLE_MASK; // Ensure val_a stays within 4 bits after potential reduction
        // Not strictly needed as GFElement.new will truncate to u4, and operations are on u8 that get truncated.
        // However, if F_POLY_U8 was > 0x1F, this might be relevant. For 0x13, it's fine.
    }
    // The result p is already within 0-15 if inputs were.
    return GFElement.new(p);
}

/// Computes base^exp in GF(16).
pub fn gf16_pow(base: GFElement, exp: usize) GFElement {
    if (exp == 0) {
        return GFElement.new(1); // g^0 = 1
    }
    var result = base;
    var i: usize = 1;
    while (i < exp) : (i += 1) {
        result = gf16_mul(result, base);
    }
    return result;
}

// Computes the inverse of a GF(16) element.
// a^(q-2) = a^(16-2) = a^14. 0 has no inverse.
pub fn gf16_inv(a: GFElement) !GFElement {
    if (a.value() == 0) {
        return error.DivisionByZero;
    }
    // In GF(16), a^15 = 1, so a^-1 = a^14.
    return gf16_pow(a, 14);
}


test "gf16 add and sub" {
    const testing = std.testing;
    try testing.expectEqual(GFElement.new(0xC), gf16_add(GFElement.new(0x5), GFElement.new(0x9)));
    try testing.expectEqual(GFElement.new(0x0), gf16_add(GFElement.new(0xA), GFElement.new(0xA)));
    try testing.expectEqual(GFElement.new(0x3), gf16_add(GFElement.new(0x3), GFElement.new(0x0)));

    try testing.expectEqual(GFElement.new(0x5), gf16_sub(GFElement.new(0xC), GFElement.new(0x9)));
    try testing.expectEqual(GFElement.new(0x0), gf16_sub(GFElement.new(0xA), GFElement.new(0xA)));
    try testing.expectEqual(GFElement.new(0x3), gf16_sub(GFElement.new(0x3), GFElement.new(0x0)));
}

test "gf16_mul by zero and one" {
    const testing = std.testing;
    try testing.expectEqual(GFElement.new(0x0), gf16_mul(GFElement.new(0x0), GFElement.new(0x5)));
    try testing.expectEqual(GFElement.new(0x0), gf16_mul(GFElement.new(0x5), GFElement.new(0x0)));
    try testing.expectEqual(GFElement.new(0x5), gf16_mul(GFElement.new(0x1), GFElement.new(0x5)));
    try testing.expectEqual(GFElement.new(0x5), gf16_mul(GFElement.new(0x5), GFElement.new(0x1)));
    try testing.expectEqual(GFElement.new(0xF), gf16_mul(GFElement.new(0xF), GFElement.new(0x1)));
}

test "gf16_mul known products" {
    const testing = std.testing;
    // x = 0x2
    try testing.expectEqual(GFElement.new(0x2), gf16_mul(GFElement.new(0x2), GFElement.new(0x1)));
    try testing.expectEqual(GFElement.new(0x4), gf16_mul(GFElement.new(0x2), GFElement.new(0x2)));
    try testing.expectEqual(GFElement.new(0x8), gf16_mul(GFElement.new(0x4), GFElement.new(0x2)));
    try testing.expectEqual(GFElement.new(0x3), gf16_mul(GFElement.new(0x8), GFElement.new(0x2))); // x^4 = x+1
    try testing.expectEqual(GFElement.new(0x6), gf16_mul(GFElement.new(0x3), GFElement.new(0x2))); // x^5
    try testing.expectEqual(GFElement.new(0xC), gf16_mul(GFElement.new(0x6), GFElement.new(0x2))); // x^6
    try testing.expectEqual(GFElement.new(0xB), gf16_mul(GFElement.new(0xC), GFElement.new(0x2))); // x^7
    try testing.expectEqual(GFElement.new(0x5), gf16_mul(GFElement.new(0xB), GFElement.new(0x2))); // x^8

    try testing.expectEqual(GFElement.new(0x8), gf16_mul(GFElement.new(0x5), GFElement.new(0x7)));
    try testing.expectEqual(GFElement.new(0x2), gf16_mul(GFElement.new(0xA), GFElement.new(0xB)));
}

test "gf16_mul commutativity" {
    const testing = std.testing;
    var i: u5 = 0; // u5 to hold 0..15
    while (i < 16) : (i += 1) {
        var j: u5 = 0;
        while (j < 16) : (j += 1) {
            try testing.expectEqual(
                gf16_mul(GFElement.new(@truncate(u8,i)), GFElement.new(@truncate(u8,j))),
                gf16_mul(GFElement.new(@truncate(u8,j)), GFElement.new(@truncate(u8,i))),
            );
        }
    }
}

test "gf16_pow" {
    const testing = std.testing;
    // x = 0x2
    try testing.expectEqual(GFElement.new(0x1), gf16_pow(GFElement.new(0x2), 0));
    try testing.expectEqual(GFElement.new(0x2), gf16_pow(GFElement.new(0x2), 1));
    try testing.expectEqual(GFElement.new(0x4), gf16_pow(GFElement.new(0x2), 2));
    try testing.expectEqual(GFElement.new(0x3), gf16_pow(GFElement.new(0x2), 4));
    try testing.expectEqual(GFElement.new(0x1), gf16_pow(GFElement.new(0x2), 15));

    try testing.expectEqual(GFElement.new(0x1), gf16_pow(GFElement.new(0x5), 0));
    try testing.expectEqual(GFElement.new(0x5), gf16_pow(GFElement.new(0x5), 1));
    try testing.expectEqual(GFElement.new(0x2), gf16_pow(GFElement.new(0x5), 2));
    try testing.expectEqual(GFElement.new(0xA), gf16_pow(GFElement.new(0x5), 3));
}

test "gf16_inv" {
    const testing = std.testing;
    // 0 has no inverse
    try testing.expectError(error.DivisionByZero, gf16_inv(GFElement.new(0)));

    // 1 is its own inverse
    try testing.expectEqual(GFElement.new(1), try gf16_inv(GFElement.new(1)));

    // Test a few pairs
    // x * x^14 = x^15 = 1. So inv(x) = x^14
    // x = 2. x^14 = (x^7)^2 = B^2 = B*B = (x^3+x^2+1)(x^3+x^2+1) = x^6+x^4+x^2 + x^4+x^2+1 = x^6+1 = C+1 = D
    // x^14 from rust test: gf16_mul(gf16_pow(gf(0x2),7), gf16_pow(gf(0x2),7)).0 -> B*B = D (0xD)
    try testing.expectEqual(gf16_pow(GFElement.new(0x2), 14), try gf16_inv(GFElement.new(0x2)));
    try testing.expectEqual(GFElement.new(0xD), try gf16_inv(GFElement.new(0x2))); // inv(x) = x^14 = 0xD
    try testing.expectEqual(GFElement.new(0x2), try gf16_inv(GFElement.new(0xD))); // Check symmetry

    // Check all non-zero elements have an inverse and inv(inv(a)) = a
    var i: u5 = 1;
    while (i < 16) : (i += 1) {
        const a = GFElement.new(@truncate(u8,i));
        const inv_a = try gf16_inv(a);
        try testing.expectEqual(GFElement.new(1), gf16_mul(a, inv_a));
        try testing.expectEqual(a, try gf16_inv(inv_a));
    }
}
