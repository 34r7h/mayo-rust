// mayo-zig/src/aes_ctr.zig

//! Implements AES-128-CTR based pseudo-random byte generation,
//! primarily for deriving P1 and P2 matrix components in MAYO.
//! NOTE: This file contains function signatures and TODOs.
//! Actual AES-CTR implementation requires a suitable Zig crypto library.

const std = @import("std");
const types = @import("types.zig");
const params_mod = @import("params.zig");

const Allocator = std.mem.Allocator;
const SeedPK = types.SeedPK;
const MayoVariantParams = params_mod.MayoVariantParams;

// TODO: Verify/select appropriate AES-CTR implementation.
// const Aes128 = std.crypto.Cipher.Aes128; 

/// Generates a stream of pseudo-random bytes using AES-128-CTR.
pub fn aes128_ctr_prng(allocator: Allocator, key_bytes: []const u8, output_len: usize) !std.ArrayList(u8) {
    _ = allocator; _ = key_bytes; _ = output_len;
    if (key_bytes.len != 16) {
        std.debug.print("AES-128 key must be 16 bytes. Provided: {}\n", .{key_bytes.len});
        return error.AesInvalidKeyLength;
    }
    std.debug.print("TODO: Implement aes128_ctr_prng using an AES-128-CTR stream cipher.\n", .{});
    return error.Unimplemented;
}

/// Derives the bytes for the P1 matrix component from a public key seed (`SeedPK`)
/// using AES-128-CTR.
pub fn derive_p1_bytes(allocator: Allocator, seed_pk: SeedPK, params: MayoVariantParams) !std.ArrayList(u8) {
    _ = allocator; _ = seed_pk; _ = params;
    if (seed_pk.get_bytes().len != params.pk_seed_bytes) {
         std.debug.print("SeedPK length {} does not match params.pk_seed_bytes {} for AES-128 key\n", .{seed_pk.get_bytes().len, params.pk_seed_bytes});
         return error.AesInvalidKeyLength;
    }
    if (params.pk_seed_bytes != 16) { 
        std.debug.print("params.pk_seed_bytes is {} but must be 16 for AES-128\n", .{params.pk_seed_bytes});
        return error.AesInvalidKeyLength;
    }
    std.debug.print("TODO: Implement derive_p1_bytes by calling aes128_ctr_prng.\n", .{});
    return error.Unimplemented;
}

/// Derives the bytes for the P2 matrix component from a public key seed (`SeedPK`)
/// using AES-128-CTR.
pub fn derive_p2_bytes(allocator: Allocator, seed_pk: SeedPK, params: MayoVariantParams) !std.ArrayList(u8) {
    _ = allocator; _ = seed_pk; _ = params;
     if (seed_pk.get_bytes().len != params.pk_seed_bytes) {
         std.debug.print("SeedPK length {} does not match params.pk_seed_bytes {} for AES-128 key\n", .{seed_pk.get_bytes().len, params.pk_seed_bytes});
         return error.AesInvalidKeyLength;
    }
    if (params.pk_seed_bytes != 16) {
        std.debug.print("params.pk_seed_bytes is {} but must be 16 for AES-128\n", .{params.pk_seed_bytes});
        return error.AesInvalidKeyLength;
    }
    std.debug.print("TODO: Implement derive_p2_bytes by calling aes128_ctr_prng.\n", .{});
    return error.Unimplemented;
}

test "aes_ctr module placeholders" {
    std.debug.print("aes_ctr.zig: Tests require AES-CTR implementation.\n", .{});
    try std.testing.expect(true);
}
