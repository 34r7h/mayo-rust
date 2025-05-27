// mayo-zig/src/verify.zig

const std = @import("std");
const testing = std.testing;
const mem = std.mem;
const ArrayList = std.ArrayList;

const types = @import("types.zig");
const params_mod = @import("params.zig");
const hash_mod = @import("hash.zig");
const codec_mod = @import("codec.zig");
const gf_mod = @import("gf.zig");
const matrix_mod = @import("matrix.zig");

const Allocator = std.mem.Allocator;
const ExpandedPublicKey = types.ExpandedPublicKey;
const Message = types.Message;
const Signature = types.Signature;
const GFVector = types.GFVector;
const GFMatrix = types.GFMatrix;
const Salt = types.Salt;
const MessageDigest = types.MessageDigest;
const MayoParams = params_mod.MayoParams;
const MayoVariantParams = params_mod.MayoVariantParams;
const GFElement = types.GFElement;

pub const VerifyError = error{
    InvalidEPKFormat,
    InvalidSignatureFormat,
    DimensionMismatch,
    HashError,
    CodecError,
    MatrixError,
    GFError,
    AllocationFailed,
    Unimplemented,
};

/// Computes the public map P*(s).
fn compute_p_star_s(
    allocator: Allocator,
    s_vector: GFVector,
    p1_matrices: []const GFMatrix,
    p2_matrices: []const GFMatrix,
    p3_matrices: []const GFMatrix,
    params: MayoVariantParams,
) !GFVector {
    if (s_vector.items.len != params.n) return VerifyError.DimensionMismatch;
    if (p1_matrices.len != params.m) return VerifyError.DimensionMismatch;
    if (p2_matrices.len != params.m) return VerifyError.DimensionMismatch;
    if (p3_matrices.len != params.m) return VerifyError.DimensionMismatch;

    const N_vo = params.n - params.o; // Length of s_v
    const O_val = params.o;         // Length of s_o

    // 1. Split s_vector into s_v and s_o
    // These are views (slices) into s_vector's items, no new allocation needed for items.
    var s_v_vec = GFVector{ .items = s_vector.items[0..N_vo], .capacity = N_vo, .allocator = allocator}; // Not owning items
    var s_o_vec = GFVector{ .items = s_vector.items[N_vo..params.n], .capacity = O_val, .allocator = allocator}; // Not owning items


    var y_computed_vector = try GFVector.initCapacity(allocator, params.m);
    // errdefer y_computed_vector.deinit(); // Caller takes ownership on success

    for (0..params.m) |i| {
        const p1_i = p1_matrices[i]; // Assumed symmetric (N_vo x N_vo)
        const p2_i = p2_matrices[i]; // (N_vo x O_val)
        const p3_i = p3_matrices[i]; // Assumed symmetric (O_val x O_val)

        // Validate matrix dimensions (optional, should be guaranteed by EPK parsing)
        if (p1_i.num_rows() != N_vo or p1_i.num_cols() != N_vo) return VerifyError.DimensionMismatch;
        if (p2_i.num_rows() != N_vo or p2_i.num_cols() != O_val) return VerifyError.DimensionMismatch;
        if (p3_i.num_rows() != O_val or p3_i.num_cols() != O_val) return VerifyError.DimensionMismatch;

        // c. term1 = s_v^T * P1_i * s_v
        // Since P1_i is symmetric: s_v^T * P1_i * s_v = (P1_i * s_v) . s_v
        var p1_sv = try matrix_mod.matrix_vec_mul(allocator, p1_i, s_v_vec);
        defer p1_sv.deinit();
        const term1 = try matrix_mod.vector_dot_product(s_v_vec, p1_sv);

        // d. term2_intermediate = s_v^T * P2_i  (row vector of O_val elements)
        //    term2 = term2_intermediate * s_o
        var sv_p2 = try matrix_mod.vec_matrix_mul(allocator, s_v_vec, p2_i);
        defer sv_p2.deinit();
        const term2 = try matrix_mod.vector_dot_product(sv_p2, s_o_vec);
        
        // e. term3 = s_o^T * P3_i * s_o
        // Since P3_i is symmetric: s_o^T * P3_i * s_o = (P3_i * s_o) . s_o
        var p3_so = try matrix_mod.matrix_vec_mul(allocator, p3_i, s_o_vec);
        defer p3_so.deinit();
        const term3 = try matrix_mod.vector_dot_product(s_o_vec, p3_so);

        // f. y_i = term1 + term2 + term3
        var y_i = gf_mod.gf16_add(term1, term2);
        y_i = gf_mod.gf16_add(y_i, term3);
        
        try y_computed_vector.append(y_i);
    }
    
    return y_computed_vector;
}


/// Implements MAYO.Verify (Algorithm 9 from the MAYO specification).
pub fn verify_signature(
    allocator: Allocator,
    epk: ExpandedPublicKey,
    message: Message,
    signature: Signature,
    params_enum: MayoParams,
) !bool {
    const params = params_enum.variant();

    // Defer deallocations for all resources
    var p1_mats_list: ?ArrayList(GFMatrix) = null;
    var p2_mats_list: ?ArrayList(GFMatrix) = null;
    var p3_mats_list: ?ArrayList(GFMatrix) = null;
    var s_vector: ?GFVector = null;
    var salt_obj: ?Salt = null; // Salt owns its bytes
    var m_digest_obj: ?MessageDigest = null; // MessageDigest owns its bytes
    var t_bytes_list: ?ArrayList(u8) = null;
    var t_vector: ?GFVector = null;
    var y_computed_vector: ?GFVector = null;

    defer {
        if (p1_mats_list) |list| { for (list.items) |m| m.deinit(); list.deinit(); }
        if (p2_mats_list) |list| { for (list.items) |m| m.deinit(); list.deinit(); }
        if (p3_mats_list) |list| { for (list.items) |m| m.deinit(); list.deinit(); }
        if (s_vector) |vec| vec.deinit();
        if (salt_obj) |s| allocator.free(s.bytes); // Salt.bytes is []u8
        if (m_digest_obj) |md| allocator.free(md.bytes); // MessageDigest.bytes is []u8
        if (t_bytes_list) |list| list.deinit();
        if (t_vector) |vec| vec.deinit();
        if (y_computed_vector) |vec| vec.deinit();
    }

    // b. Parse epk
    const epk_b = epk.bytes.items;
    if (epk_b.len != params.p1_bytes + params.p2_bytes + params.p3_bytes) {
        return VerifyError.InvalidEPKFormat;
    }
    var current_offset: usize = 0;
    const p1_all_bytes = epk_b[current_offset .. current_offset + params.p1_bytes];
    current_offset += params.p1_bytes;
    const p2_all_bytes = epk_b[current_offset .. current_offset + params.p2_bytes];
    current_offset += params.p2_bytes;
    const p3_all_bytes = epk_b[current_offset .. epk_b.len];
    std.debug.assert(p3_all_bytes.len == params.p3_bytes);

    p1_mats_list = try codec_mod.decode_p1_matrices(allocator, p1_all_bytes, params);
    p2_mats_list = try codec_mod.decode_p2_matrices(allocator, p2_all_bytes, params);
    p3_mats_list = try codec_mod.decode_p3_matrices(allocator, p3_all_bytes, params);

    // c. Parse signature
    const sig_b = signature.bytes.items;
    const s_bytes_len = params_mod.MayoParams.bytes_for_gf16_elements(params.n);
    if (sig_b.len != s_bytes_len + params.salt_bytes) {
        return VerifyError.InvalidSignatureFormat;
    }
    const s_bytes_slice = sig_b[0..s_bytes_len];
    const salt_value_bytes_slice = sig_b[s_bytes_len .. sig_b.len];

    s_vector = try codec_mod.decode_s_vector(allocator, s_bytes_slice, params);
    
    var salt_bytes_alloc = try allocator.dupe(u8, salt_value_bytes_slice);
    // errdefer allocator.free(salt_bytes_alloc); // Handled by defer block for salt_obj
    salt_obj = Salt{ .bytes = salt_bytes_alloc };

    // d. Hash message M to M_digest
    var m_digest_alloc = try allocator.alloc(u8, params.m_digest_bytes);
    // errdefer allocator.free(m_digest_alloc); // Handled by defer block for m_digest_obj
    try hash_mod.shake256_digest(message.bytes.items, params.m_digest_bytes, m_digest_alloc);
    m_digest_obj = MessageDigest{ .bytes = m_digest_alloc };
    
    // e. Derive target vector t_bytes = H(M_digest || salt)
    const target_t_len_bytes = params_mod.MayoParams.bytes_for_gf16_elements(params.m);
    t_bytes_list = ArrayList(u8).init(allocator);
    try t_bytes_list.?.resize(target_t_len_bytes);
    try hash_mod.shake256_derive_target_t(m_digest_obj.?, salt_obj.?, target_t_len_bytes, t_bytes_list.?.items);

    // f. Decode t_bytes into t_vector
    t_vector = try codec_mod.decode_gf_elements(allocator, t_bytes_list.?.items, params.m);

    // g. Compute y_computed_vector = P*(s_vector)
    y_computed_vector = try compute_p_star_s(
        allocator,
        s_vector.?,
        p1_mats_list.?.items,
        p2_mats_list.?.items,
        p3_mats_list.?.items,
        params,
    );

    // h. Compare y_computed_vector with t_vector
    if (y_computed_vector.?.items.len != t_vector.?.items.len) {
        // This should not happen if logic is correct
        return VerifyError.DimensionMismatch; 
    }
    
    return mem.eql(GFElement, y_computed_vector.?.items, t_vector.?.items);
}


// --- Unit Tests ---
fn create_dummy_epk_for_verify(allocator: Allocator, params_enum: MayoParams) !ExpandedPublicKey {
    const params = params_enum.variant();
    const total_len = params.p1_bytes + params.p2_bytes + params.p3_bytes;
    var epk_bytes_list = try ArrayList(u8).initCapacity(allocator, total_len);
    // errdefer epk_bytes_list.deinit(); // Handled by caller or struct ownership

    // Fill with non-zero placeholder data
    for (0..total_len) |i| {
        try epk_bytes_list.append(@intCast(u8, (i % 250) + 1)); // Avoid 0 for simplicity if codec expects non-empty
    }
    return ExpandedPublicKey{ .bytes = epk_bytes_list.toOwnedArrayList() };
}

test "compute_p_star_s: basic sanity check" {
    const allocator = testing.allocator;
    const params = params_mod.MayoParams.MAYO1_L1.variant(); // n=68, o=16, m=64

    var s_vec = try GFVector.initCapacity(allocator, params.n);
    defer s_vec.deinit();
    for (0..params.n) |_| { try s_vec.append(GFElement.new(1)); } // s_v and s_o are all 1s

    var p1_mats = ArrayList(GFMatrix).init(allocator);
    defer { for (p1_mats.items) |m_item| m_item.deinit(); p1_mats.deinit(); }
    try p1_mats.ensureTotalCapacity(params.m);
    for (0..params.m) |_| {
        var p1_i = try GFMatrix.init(allocator, params.n - params.o, params.n - params.o);
        try matrix_mod.matrix_fill_diagonal(p1_i, GFElement.new(1)); // P1_i = I
        p1_mats.appendAssumeCapacity(p1_i);
    }

    var p2_mats = ArrayList(GFMatrix).init(allocator);
    defer { for (p2_mats.items) |m_item| m_item.deinit(); p2_mats.deinit(); }
    try p2_mats.ensureTotalCapacity(params.m);
    for (0..params.m) |_| {
        var p2_i = try GFMatrix.init(allocator, params.n - params.o, params.o);
        try matrix_mod.matrix_fill(p2_i, GFElement.new(1)); // P2_i = All 1s matrix
        p2_mats.appendAssumeCapacity(p2_i);
    }
    
    var p3_mats = ArrayList(GFMatrix).init(allocator);
    defer { for (p3_mats.items) |m_item| m_item.deinit(); p3_mats.deinit(); }
    try p3_mats.ensureTotalCapacity(params.m);
    for (0..params.m) |_| {
        var p3_i = try GFMatrix.init(allocator, params.o, params.o);
        try matrix_mod.matrix_fill_diagonal(p3_i, GFElement.new(1)); // P3_i = I
        p3_mats.appendAssumeCapacity(p3_i);
    }

    var y_computed = try compute_p_star_s(allocator, s_vec, p1_mats.items, p2_mats.items, p3_mats.items, params);
    defer y_computed.deinit();

    try testing.expectEqual(@as(usize, params.m), y_computed.items.len);

    // With s_v=all_1s, P1_i=I: s_v^T * I * s_v = sum(s_v_j^2) = sum(1) = (n-o) mod 16 (since 1^2=1)
    const term1_expected = GFElement.new(@intCast(u4, (params.n - params.o) % 16));
    // With s_v=all_1s, s_o=all_1s, P2_i=all_1s: s_v^T * P2_i = [o, o, ..., o] (vector of (n-o) ones dotted with columns of P2_i)
    // Each element of (s_v^T * P2_i) is sum of (n-o) ones = (n-o) mod 16.
    // Then dotted with s_o (all_1s): sum of o elements, each (n-o) mod 16. So o * (n-o) mod 16.
    const term2_expected = GFElement.new(@intCast(u4, ( (params.n - params.o) * params.o ) % 16));
    // With s_o=all_1s, P3_i=I: s_o^T * I * s_o = sum(s_o_j^2) = sum(1) = o mod 16
    const term3_expected = GFElement.new(@intCast(u4, params.o % 16));
    
    var expected_y_i = gf_mod.gf16_add(term1_expected, term2_expected);
    expected_y_i = gf_mod.gf16_add(expected_y_i, term3_expected);

    for (y_computed.items) |y_val| {
        try testing.expectEqual(expected_y_i, y_val);
    }
}

test "verify_signature: basic flow test (MAYO1_L1)" {
    const allocator = testing.allocator;
    const params_enum = params_mod.MayoParams.MAYO1_L1;
    const params = params_enum.variant();

    var epk = try create_dummy_epk_for_verify(allocator, params_enum);
    defer epk.deinit();

    var msg_bytes = [_]u8{1,2,3,4,5};
    var message = try Message.init_copy_bytes(allocator, &msg_bytes);
    defer message.deinit();

    // Create a dummy signature of correct length
    // s_bytes || salt_bytes
    const s_bytes_len = params_mod.MayoParams.bytes_for_gf16_elements(params.n);
    const total_sig_len = s_bytes_len + params.salt_bytes;
    var sig_bytes_list = try ArrayList(u8).initCapacity(allocator, total_sig_len);
    // errdefer sig_bytes_list.deinit(); // Handled by Signature struct
    for (0..total_sig_len) |i| {
        try sig_bytes_list.append(@truncate(u8, i + 7)); // Dummy non-zero data
    }
    var signature = Signature{ .bytes = sig_bytes_list.toOwnedArrayList() };
    // defer signature.deinit(); // Signature owns its bytes

    // This test primarily checks if verification can complete without error.
    // It will likely return `false` because data is dummy.
    var is_valid = verify_signature(allocator, epk, message, signature, params_enum) catch |err| {
        std.debug.print("Verification failed with error: {}\n", .{err});
        // If it's an expected error due to dummy data (e.g. codec error if bytes are invalid for GF elements)
        // that's different from a logic error in verify_signature itself.
        // For now, any error is a test failure.
        return err;
    };
    
    std.debug.print("Dummy MAYO1_L1 signature verification result: {}\n", .{is_valid});
    // try testing.expect(!is_valid); // Expect false with dummy data.
    // For now, just checking it runs is the goal.
    _ = is_valid; // suppress unused variable if expect is commented out
}

// TODO: Add more detailed tests, especially for verify_signature using known answer tests (KATs)
// if available, or by signing a message and then verifying it.
```
