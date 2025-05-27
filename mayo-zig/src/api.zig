// mayo-zig/src/api.zig

const std = @import("std");
const testing = std.testing;
const mem = std.mem;
const ArrayList = std.ArrayList;

const types = @import("types.zig");
const params_mod = @import("params.zig");
const keygen_mod = @import("keygen.zig");
const sign_mod = @import("sign.zig");
const verify_mod = @import("verify.zig");

const Allocator = std.mem.Allocator;
const CompactSecretKey = types.CompactSecretKey;
const CompactPublicKey = types.CompactPublicKey;
const Signature = types.Signature;
const Message = types.Message;
const MayoParams = params_mod.MayoParams;
const ExpandedSecretKey = types.ExpandedSecretKey;
const ExpandedPublicKey = types.ExpandedPublicKey;

pub const ApiError = error{
    UnknownMayoVariant,
    InvalidKeyFormat,
    InvalidSignatureFormat,
    InvalidMessageFormat, // For signed_message_bytes too short
    VerificationFailed, // Specifically when signature is cryptographically invalid
    AllocationFailed,
    // Errors propagated from other modules
    KeygenError,
    SignError,
    VerifyError,
    CodecError, // If params.zig values are incorrect, leading to codec issues
    Unimplemented, // Should not be used in final version
};


/// Wrapper struct for returning a keypair.
pub const KeyPairWrapper = struct {
    sk: CompactSecretKey,
    pk: CompactPublicKey,

    pub fn deinit(self: KeyPairWrapper) void {
        self.sk.deinit();
        self.pk.deinit();
    }
};

/// Generates a compact key pair (secret key, public key) for the specified MAYO variant.
pub export fn keypair(allocator: Allocator, mayo_variant_name: []const u8) !KeyPairWrapper {
    const params_enum = params_mod.MayoParams.get_params_by_name(mayo_variant_name) orelse return ApiError.UnknownMayoVariant;

    var key_pair_gen = try keygen_mod.compact_key_gen(allocator, params_enum) catch |err| {
        // Map keygen errors if needed, or assume they are a superset or compatible
        if (err == error.HashError) return ApiError.KeygenError; // Example mapping
        if (err == error.AllocationFailed) return ApiError.AllocationFailed;
        return ApiError.KeygenError; // Generic mapping
    };
    
    // key_pair_gen.sk and key_pair_gen.pk are already CompactSecretKey and CompactPublicKey
    return KeyPairWrapper{ .sk = key_pair_gen.sk, .pk = key_pair_gen.pk };
}

/// Signs a message using a compact secret key.
/// The returned signature does not include the message.
pub export fn sign(
    allocator: Allocator,
    csk_bytes: []const u8,
    message_bytes: []const u8,
    mayo_variant_name: []const u8,
) !ArrayList(u8) {
    const params_enum = params_mod.MayoParams.get_params_by_name(mayo_variant_name) orelse return ApiError.UnknownMayoVariant;
    const params_variant = params_enum.variant();

    // Validate csk_bytes length against params.sk_seed_bytes
    if (csk_bytes.len != params_variant.sk_seed_bytes) {
        return ApiError.InvalidKeyFormat;
    }

    var csk_obj = try CompactSecretKey.init_copy_bytes(allocator, csk_bytes) catch |err| {
        if (err == error.AllocationFailed) return ApiError.AllocationFailed;
        return ApiError.InvalidKeyFormat; // Or map more specifically
    };
    defer csk_obj.deinit();

    var msg_obj = try Message.init_copy_bytes(allocator, message_bytes) catch |err| {
        if (err == error.AllocationFailed) return ApiError.AllocationFailed;
        return ApiError.InvalidMessageFormat;
    };
    defer msg_obj.deinit();

    var esk_obj = try keygen_mod.expand_sk(allocator, csk_obj, params_enum) catch |err| {
        // Map keygen_mod.KeygenError to ApiError
        switch (err) {
            error.AllocationFailed => return ApiError.AllocationFailed,
            error.InvalidInputKey => return ApiError.InvalidKeyFormat,
            error.HashError, error.AesError, error.CodecError, error.MatrixError => return ApiError.KeygenError, // Internal error during expansion
            else => return ApiError.KeygenError,
        }
    };
    defer esk_obj.deinit();

    var sig_obj = try sign_mod.sign_message(allocator, esk_obj, msg_obj, params_enum) catch |err| {
        // Map sign_mod.SignError to ApiError
        switch (err) {
            error.AllocationFailed => return ApiError.AllocationFailed,
            error.SignMaxRetriesExceeded => return ApiError.SignError, // Or a specific ApiError.MaxRetries
            error.InvalidESKFormat, error.HashError, error.CodecError, error.SolverError, 
            error.MatrixError, error.GFError, error.DimensionMismatch => return ApiError.SignError, // Internal error during signing
            else => return ApiError.SignError,
        }
    };
    defer sig_obj.deinit();

    // Clone the signature bytes into a new ArrayList to return (caller owns it)
    var return_sig_bytes = try ArrayList(u8).init_slice_clone(allocator, sig_obj.bytes.items) catch |err| {
        if (err == error.OutOfMemory) return ApiError.AllocationFailed;
        return ApiError.AllocationFailed; // Should map to OOM more generally
    };
    
    return return_sig_bytes;
}

/// Verifies a signature on a "signed message" and recovers the original message if valid.
/// Assumes `signed_message_bytes` is `signature_bytes || original_message_bytes`.
/// Returns `null` if signature is invalid, otherwise returns the original message bytes.
pub export fn open(
    allocator: Allocator,
    cpk_bytes: []const u8,
    signed_message_bytes: []const u8,
    mayo_variant_name: []const u8,
) !?ArrayList(u8) {
    const params_enum = params_mod.MayoParams.get_params_by_name(mayo_variant_name) orelse return ApiError.UnknownMayoVariant;
    const params_variant = params_enum.variant();

    // Validate cpk_bytes length
    if (cpk_bytes.len != params_variant.pk_seed_bytes + params_variant.p3_bytes) {
        return ApiError.InvalidKeyFormat;
    }

    var cpk_obj = try CompactPublicKey.init_copy_bytes(allocator, cpk_bytes) catch |err| {
        if (err == error.AllocationFailed) return ApiError.AllocationFailed;
        return ApiError.InvalidKeyFormat;
    };
    defer cpk_obj.deinit();

    const sig_len = params_mod.MayoParams.bytes_for_gf16_elements(params_variant.n) + params_variant.salt_bytes;

    if (signed_message_bytes.len < sig_len) {
        return ApiError.InvalidSignatureFormat; // Or InvalidMessageFormat as it's too short to contain sig
    }

    const sig_bytes_slice = signed_message_bytes[0..sig_len];
    const original_message_slice = signed_message_bytes[sig_len..];

    var sig_obj = try Signature.init_copy_bytes(allocator, sig_bytes_slice) catch |err| {
        if (err == error.AllocationFailed) return ApiError.AllocationFailed;
        return ApiError.InvalidSignatureFormat;
    };
    defer sig_obj.deinit();

    var original_msg_obj = try Message.init_copy_bytes(allocator, original_message_slice) catch |err| {
        if (err == error.AllocationFailed) return ApiError.AllocationFailed;
        return ApiError.InvalidMessageFormat; // Or some other error if message part is problematic
    };
    defer original_msg_obj.deinit();

    var epk_obj = try keygen_mod.expand_pk(allocator, cpk_obj, params_enum) catch |err| {
         switch (err) {
            error.AllocationFailed => return ApiError.AllocationFailed,
            error.InvalidInputKey => return ApiError.InvalidKeyFormat,
            error.HashError, error.AesError, error.CodecError => return ApiError.KeygenError,
            else => return ApiError.KeygenError,
        }
    };
    defer epk_obj.deinit();

    const is_valid = try verify_mod.verify_signature(allocator, epk_obj, original_msg_obj, sig_obj, params_enum) catch |err| {
        // Map verify_mod.VerifyError to ApiError
        switch (err) {
            error.AllocationFailed => return ApiError.AllocationFailed,
            error.InvalidEPKFormat, error.InvalidSignatureFormat, 
            error.DimensionMismatch, error.HashError, error.CodecError, 
            error.MatrixError, error.GFError => return ApiError.VerifyError, // Internal error during verification
            else => return ApiError.VerifyError,
        }
    };

    if (is_valid) {
        var return_message_bytes = try ArrayList(u8).init_slice_clone(allocator, original_message_slice) catch |err| {
             if (err == error.OutOfMemory) return ApiError.AllocationFailed;
             return ApiError.AllocationFailed;
        };
        return return_message_bytes;
    } else {
        return null; // Cryptographic verification failed
    }
}


// --- Unit Tests ---
test "api: keypair generation - valid variants" {
    const allocator = testing.allocator;
    const variants = [_][]const u8{ "MAYO1_L1", "MAYO2_L1", "MAYO3_L1", "MAYO1_L3", "MAYO2_L3", "MAYO3_L3", "MAYO1_L5", "MAYO2_L5", "MAYO3_L5" }; // Add all supported
    
    for (variants) |variant_name_bytes| {
        if (params_mod.MayoParams.get_params_by_name(variant_name_bytes) == null) {
            std.debug.print("Skipping test for variant {s} as it's not in params_mod.MayoParams\n", .{variant_name_bytes});
            continue;
        }
        std.debug.print("Testing keypair generation for {s}\n", .{variant_name_bytes});
        var kp = try keypair(allocator, variant_name_bytes);
        defer kp.deinit();
        
        const params_enum = params_mod.MayoParams.get_params_by_name(variant_name_bytes).?;
        const params_variant = params_enum.variant();

        try testing.expect(kp.sk.bytes.items.len == params_variant.sk_seed_bytes);
        try testing.expect(kp.pk.bytes.items.len == params_variant.pk_seed_bytes + params_variant.p3_bytes);
        try testing.expect(kp.sk.bytes.items.len > 0);
        try testing.expect(kp.pk.bytes.items.len > 0);
    }
}

test "api: keypair generation - invalid variant" {
    const allocator = testing.allocator;
    const invalid_name = "MAYO_INVALID";
    var result = keypair(allocator, invalid_name);
    try testing.expectError(ApiError.UnknownMayoVariant, result);
}

test "api: sign and open round trip" {
    const allocator = testing.allocator;
    // Test with a specific variant, e.g., MAYO1_L1
    const variant_name = "MAYO1_L1";
    const params_enum = params_mod.MayoParams.get_params_by_name(variant_name) orelse {
        std.debug.print("Skipping round trip test: {s} not found\n", .{variant_name});
        return;
    };
    const params_variant = params_enum.variant();

    std.debug.print("Testing sign/open round trip for {s}\n", .{variant_name});

    // 1. Generate keypair
    var kp = try keypair(allocator, variant_name);
    defer kp.deinit();

    // 2. Sign a message
    const message_content = "This is a test message for MAYO.";
    var signature_bytes_list = try sign(allocator, kp.sk.bytes.items, message_content, variant_name);
    defer signature_bytes_list.deinit();

    try testing.expect(signature_bytes_list.items.len == params_mod.MayoParams.bytes_for_gf16_elements(params_variant.n) + params_variant.salt_bytes);

    // 3. Prepare signed message for open
    var signed_message_list = ArrayList(u8).init(allocator);
    defer signed_message_list.deinit();
    try signed_message_list.appendSlice(signature_bytes_list.items);
    try signed_message_list.appendSlice(message_content);

    // 4. Open (verify and recover message)
    var recovered_message_list_opt = try open(allocator, kp.pk.bytes.items, signed_message_list.items, variant_name);
    
    try testing.expect(recovered_message_list_opt != null); // Expect verification to succeed
    if (recovered_message_list_opt) |recovered_message_list| {
        defer recovered_message_list.deinit();
        try testing.expectEqualSlices(u8, message_content, recovered_message_list.items);
        std.debug.print("Round trip successful for {s}\n", .{variant_name});
    } else {
        std.debug.print("Round trip failed for {s}, signature did not verify.\n", .{variant_name});
        try testing.expect(false); // Force test failure
    }
}

test "api: open with tampered signature" {
    const allocator = testing.allocator;
    const variant_name = "MAYO1_L1";
     const params_enum = params_mod.MayoParams.get_params_by_name(variant_name) orelse {
        std.debug.print("Skipping tampered signature test: {s} not found\n", .{variant_name});
        return;
    };

    var kp = try keypair(allocator, variant_name);
    defer kp.deinit();

    const message_content = "Another test message.";
    var signature_bytes_list = try sign(allocator, kp.sk.bytes.items, message_content, variant_name);
    defer signature_bytes_list.deinit();

    // Tamper the signature (e.g., flip a bit)
    if (signature_bytes_list.items.len > 0) {
        signature_bytes_list.items[0] +%= 1; 
    }

    var signed_message_list = ArrayList(u8).init(allocator);
    defer signed_message_list.deinit();
    try signed_message_list.appendSlice(signature_bytes_list.items);
    try signed_message_list.appendSlice(message_content);

    var recovered_message_list_opt = try open(allocator, kp.pk.bytes.items, signed_message_list.items, variant_name);
    
    try testing.expect(recovered_message_list_opt == null); // Expect verification to fail
    std.debug.print("Tampered signature test successful for {s} (verification failed as expected)\n", .{variant_name});
}

test "api: open with short signed_message_bytes" {
    const allocator = testing.allocator;
    const variant_name = "MAYO1_L1";
    const params_enum = params_mod.MayoParams.get_params_by_name(variant_name) orelse {
        std.debug.print("Skipping short signed_message test: {s} not found\n", .{variant_name});
        return;
    };

    var kp = try keypair(allocator, variant_name);
    defer kp.deinit();
    
    const short_signed_msg = [_]u8{1,2,3}; // Definitely too short
    var result = open(allocator, kp.pk.bytes.items, &short_signed_msg, variant_name);
    try testing.expectError(ApiError.InvalidSignatureFormat, result);
}

```
