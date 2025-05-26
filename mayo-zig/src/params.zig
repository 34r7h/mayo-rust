// mayo-zig/src/params.zig

//! Defines parameters for different MAYO security levels.
const std = @import("std");

/// Irreducible polynomial for GF(16): x^4 + x + 1
/// (coefficients in little-endian for degree, e.g., 0b...c3 c2 c1 c0)
/// x^4 + x + 1 is 1*x^4 + 0*x^3 + 0*x^2 + 1*x^1 + 1*x^0 -> 10011
pub const F_POLY_U8: u8 = 0b00010011;
pub const F_POLY_U16: u16 = 0x13;

/// Holds the specific parameters for a MAYO variant (e.g., MAYO1, MAYO2).
pub const MayoVariantParams = struct {
    // Core MQ parameters
    n: usize, // Number of variables (elements in a solution vector s)
    m: usize, // Number of equations in P (elements in t)
    o: usize, // Number of vinegar variables
    k: usize, // Number of solutions to find / oil variables used in G

    // Byte lengths for seeds, salts, digests
    sk_seed_bytes: usize, // Security parameter lambda
    pk_seed_bytes: usize, // For PK seed (Note: AES key size for P1/P2 derivation)
    salt_bytes: usize, // For salt in signature
    digest_bytes: usize, // For message digest (e.g., SHAKE256 output length)

    // Byte lengths for various components derived from seeds or used in the scheme
    o_bytes: usize, // Serialized oil variables component (e.g., G or its seed)
    p1_bytes: usize, // Serialized P1 matrix component (derived via AES-CTR from pk_seed)
    p2_bytes: usize, // Serialized P2 matrix component (derived via AES-CTR from pk_seed)
    p3_bytes: usize, // Serialized P3 matrix component (derived via SHAKE from pk_seed)
};

/// Enum to select a specific set of MAYO parameters.
pub const MayoParams = union(enum) {
    MAYO1: MayoVariantParams,
    MAYO2: MayoVariantParams,
    // Potentially MAYO3, MAYO5 in the future

    /// Field characteristic (GF(2^4) means q=16).
    pub const Q: usize = 16;

    /// Parameters for MAYO1 (NIST Level 1 equivalent).
    pub fn mayo1() MayoParams {
        return .{
            .MAYO1 = .{
                .n = 66, .m = 64, .o = 8, .k = 9,
                .sk_seed_bytes = 24,
                .pk_seed_bytes = 16,
                .salt_bytes = 24,
                .digest_bytes = 32,
                .o_bytes = 232,
                .p1_bytes = 54784,
                .p2_bytes = 14848,
                .p3_bytes = 1152,
            }
        };
    }

    /// Parameters for MAYO2 (NIST Level 3 equivalent, if mapping directly).
    pub fn mayo2() MayoParams {
        return .{
            .MAYO2 = .{
                .n = 78, .m = 64, .o = 18, .k = 4,
                .sk_seed_bytes = 24,
                .pk_seed_bytes = 16,
                .salt_bytes = 24,
                .digest_bytes = 32,
                .o_bytes = 540,
                .p1_bytes = 58560,
                .p2_bytes = 34560,
                .p3_bytes = 5504,
            }
        };
    }

    /// Accessor method to get the underlying `MayoVariantParams`.
    pub fn variant(self: MayoParams) *const MayoVariantParams {
        return switch (self) {
            .MAYO1 => &self.MAYO1,
            .MAYO2 => &self.MAYO2,
        };
    }

    /// Helper method to calculate bytes needed to store a given number of GF(16) elements.
    /// Each GF(16) element is 4 bits (a nibble).
    pub fn bytes_for_gf16_elements(num_elements: usize) usize {
        return (num_elements + 1) / 2;
    }

    // Convenience accessors
    pub fn n(self: MayoParams) usize { return self.variant().n; }
    pub fn m(self: MayoParams) usize { return self.variant().m; }
    pub fn o(self: MayoParams) usize { return self.variant().o; }
    pub fn k(self: MayoParams) usize { return self.variant().k; }
    pub fn sk_seed_bytes(self: MayoParams) usize { return self.variant().sk_seed_bytes; }
    pub fn pk_seed_bytes(self: MayoParams) usize { return self.variant().pk_seed_bytes; }
    pub fn salt_bytes(self: MayoParams) usize { return self.variant().salt_bytes; }
    pub fn digest_bytes(self: MayoParams) usize { return self.variant().digest_bytes; }
    pub fn o_bytes(self: MayoParams) usize { return self.variant().o_bytes; }
    pub fn p1_bytes(self: MayoParams) usize { return self.variant().p1_bytes; }
    pub fn p2_bytes(self: MayoParams) usize { return self.variant().p2_bytes; }
    pub fn p3_bytes(self: MayoParams) usize { return self.variant().p3_bytes; }

    pub fn get_params_by_name(name: []const u8) !MayoParams {
        if (std.ascii.eqlIgnoreCase(name, "mayo1")) {
            return MayoParams.mayo1();
        } else if (std.ascii.eqlIgnoreCase(name, "mayo2")) {
            return MayoParams.mayo2();
        } else {
            // TODO: How to handle error formatting like Rust's format! ?
            // For now, returning a generic error.
            // std.debug.print("Unknown MAYO variant name: {s}\n", .{name});
            return error.UnknownMayoVariant;
        }
    }
};

test "mayo1 parameters" {
    const params = MayoParams.mayo1();
    try std.testing.expectEqual(@as(usize, 66), params.n());
    try std.testing.expectEqual(@as(usize, 64), params.m());
    try std.testing.expectEqual(@as(usize, 8), params.o());
    try std.testing.expectEqual(@as(usize, 9), params.k());
    try std.testing.expectEqual(@as(usize, 24), params.sk_seed_bytes());
    try std.testing.expectEqual(@as(usize, 16), params.pk_seed_bytes());
    try std.testing.expectEqual(@as(usize, 24), params.salt_bytes());
    try std.testing.expectEqual(@as(usize, 32), params.digest_bytes());
    try std.testing.expectEqual(@as(usize, 232), params.o_bytes());
    try std.testing.expectEqual(@as(usize, 54784), params.p1_bytes());
    try std.testing.expectEqual(@as(usize, 14848), params.p2_bytes());
    try std.testing.expectEqual(@as(usize, 1152), params.p3_bytes());

    const variant_params = params.variant();
    try std.testing.expectEqual(@as(usize, 66), variant_params.n);
}

test "mayo2 parameters" {
    const params = MayoParams.mayo2();
    try std.testing.expectEqual(@as(usize, 78), params.n());
    try std.testing.expectEqual(@as(usize, 18), params.o());
    try std.testing.expectEqual(@as(usize, 540), params.o_bytes());
    try std.testing.expectEqual(@as(usize, 58560), params.p1_bytes());
    try std.testing.expectEqual(@as(usize, 34560), params.p2_bytes());
    try std.testing.expectEqual(@as(usize, 5504), params.p3_bytes());
}

test "bytes_for_gf16_elements" {
    try std.testing.expectEqual(@as(usize, 0), MayoParams.bytes_for_gf16_elements(0));
    try std.testing.expectEqual(@as(usize, 1), MayoParams.bytes_for_gf16_elements(1));
    try std.testing.expectEqual(@as(usize, 1), MayoParams.bytes_for_gf16_elements(2));
    try std.testing.expectEqual(@as(usize, 2), MayoParams.bytes_for_gf16_elements(3));
    try std.testing.expectEqual(@as(usize, 2), MayoParams.bytes_for_gf16_elements(4));
}

test "get_params_by_name" {
    const p_mayo1 = try MayoParams.get_params_by_name("mayo1");
    try std.testing.expectEqual(p_mayo1.n(), MayoParams.mayo1().n());

    const p_MAYOO1 = try MayoParams.get_params_by_name("MAYO1");
    try std.testing.expectEqual(p_MAYOO1.n(), MayoParams.mayo1().n());
    
    const p_mayo2 = try MayoParams.get_params_by_name("mayo2");
    try std.testing.expectEqual(p_mayo2.n(), MayoParams.mayo2().n());

    const p_invalid = MayoParams.get_params_by_name("mayo3");
    try std.testing.expectError(error.UnknownMayoVariant, p_invalid);
}
