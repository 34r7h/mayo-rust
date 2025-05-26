// mayo-zig/src/api.zig

//! Defines the public API for the MAYO Zig library, including functions for key generation, signing, and opening.
//! These functions will be candidates for WASM export.
//! NOTE: This file contains function signatures and TODOs. Full implementation is pending.

const std = @import("std");
const types = @import("types.zig");
const params_mod = @import("params.zig");
const keygen_mod = @import("keygen.zig");
const sign_mod = @import("sign.zig");
const verify_mod = @import("verify.zig");
// May also need codec if dealing with raw byte slices for API boundaries.

const Allocator = std.mem.Allocator;
const CompactSecretKey = types.CompactSecretKey;
const CompactPublicKey = types.CompactPublicKey;
const Signature = types.Signature;
const Message = types.Message;
const MayoParams = params_mod.MayoParams;

/// Wrapper struct for returning a keypair.
/// For WASM, it might be easier to return sk and pk as separate byte slices
/// or have functions to extract them from these structs.
pub const KeyPairWrapper = struct {
    sk: CompactSecretKey,
    pk: CompactPublicKey,

    // Deinit is needed if this struct owns the keys.
    // Assumes CompactSecretKey and CompactPublicKey have their own deinit methods.
    pub fn deinit(self: KeyPairWrapper) void {
        self.sk.deinit();
        self.pk.deinit();
    }
};

/// Generates a compact key pair (secret key, public key) for the specified MAYO variant.
/// This wraps `MAYO.CompactKeyGen`.
///
/// WASM Export considerations:
/// - `mayo_variant_name` as `[]const u8`.
/// - Return type might need to be more WASM-friendly, e.g., separate functions to get sk/pk bytes,
///   or a struct that directly holds `ArrayList(u8)` for sk and pk if KeyPairWrapper is problematic.
pub export fn keypair(allocator: Allocator, mayo_variant_name: []const u8) !KeyPairWrapper {
    _ = allocator; _ = mayo_variant_name;
    std.debug.print("TODO: Implement API function keypair.\n", .{});
    // 1. Parse mayo_variant_name to get MayoParams enum.
    //    Use params_mod.MayoParams.get_params_by_name(mayo_variant_name).
    // 2. Call keygen_mod.compact_key_gen(allocator, params_enum).
    // 3. Wrap the result in KeyPairWrapper.
    return error.Unimplemented;
}

/// Signs a message using a compact secret key.
/// The returned signature does not include the message.
///
/// WASM Export considerations:
/// - `csk_bytes` as `[]const u8`.
/// - `message_bytes` as `[]const u8`.
/// - `mayo_variant_name` as `[]const u8`.
/// - Return type `std.ArrayList(u8)` for the signature bytes.
pub export fn sign(allocator: Allocator, csk_bytes: []const u8, message_bytes: []const u8, mayo_variant_name: []const u8) !std.ArrayList(u8) {
    _ = allocator; _ = csk_bytes; _ = message_bytes; _ = mayo_variant_name;
    std.debug.print("TODO: Implement API function sign.\n", .{});
    // 1. Parse mayo_variant_name to get MayoParams.
    // 2. Create CompactSecretKey from csk_bytes.
    // 3. Create Message from message_bytes.
    // 4. Call sign_mod.sign_message(allocator, esk, message, params_enum).
    //    This implies expand_sk is called within sign_message or here.
    //    The Rust api.rs calls expand_sk first, then sign_message with the expanded key.
    //    Let's follow that:
    //    a. `esk = try keygen_mod.expand_sk(allocator, csk_obj, params_enum);`
    //    b. `sig_obj = try sign_mod.sign_message(allocator, esk, msg_obj, params_enum);`
    // 5. Return sig_obj.get_bytes() as a new ArrayList or handle ownership carefully.
    return error.Unimplemented;
}

/// Verifies a signature on a "signed message" and recovers the original message if valid.
/// Assumes `signed_message_bytes` is `signature_bytes || original_message_bytes`.
/// Returns `null` if signature is invalid, otherwise returns the original message bytes.
///
/// WASM Export considerations:
/// - `cpk_bytes` as `[]const u8`.
/// - `signed_message_bytes` as `[]const u8`.
/// - `mayo_variant_name` as `[]const u8`.
/// - Return type `?std.ArrayList(u8)` (nullable ArrayList for message).
pub export fn open(allocator: Allocator, cpk_bytes: []const u8, signed_message_bytes: []const u8, mayo_variant_name: []const u8) !?std.ArrayList(u8) {
    _ = allocator; _ = cpk_bytes; _ = signed_message_bytes; _ = mayo_variant_name;
    std.debug.print("TODO: Implement API function open.\n", .{});
    // 1. Parse mayo_variant_name to get MayoParams.
    // 2. Create CompactPublicKey from cpk_bytes.
    // 3. Determine signature length based on params (e.g., params.variant().n, params.variant().salt_bytes).
    //    Use MayoParams.bytes_for_gf16_elements(params.variant().n) + params.variant().salt_bytes.
    // 4. Split signed_message_bytes into sig_bytes and original_message_bytes.
    // 5. Create Signature object from sig_bytes.
    // 6. Create Message object from original_message_bytes.
    // 7. Call verify_mod.verify_signature(allocator, epk, original_msg_obj, sig_obj, params_enum).
    //    This implies expand_pk is called first:
    //    a. `epk = try keygen_mod.expand_pk(allocator, cpk_obj, params_enum);`
    //    b. `is_valid = try verify_mod.verify_signature(allocator, epk, original_msg_obj, sig_obj, params_enum);`
    // 8. If is_valid is true, return a copy of original_message_bytes.
    // 9. If is_valid is false, return null.
    return error.Unimplemented;
}


test "api module placeholders" {
    std.debug.print("api.zig: All functions are placeholders and need implementation.\n", .{});
    // Example of how a function might be called
    // const allocator = std.testing.allocator;
    // _ = keypair(allocator, "mayo1") catch |err| {
    //    try std.testing.expect(err == error.Unimplemented);
    // };
    try std.testing.expect(true);
}
