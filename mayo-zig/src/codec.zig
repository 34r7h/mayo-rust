const std = @import("std");
const testing = std.testing;
const mem = std.mem;
const ArrayList = std.ArrayList;

const types = @import("types.zig");
const params_mod = @import("params.zig");
const matrix_mod = @import("matrix.zig"); // For GFMatrix type and potentially constructors

const Allocator = std.mem.Allocator;
const GFElement = types.GFElement;
const GFVector = types.GFVector;
const GFMatrix = types.GFMatrix;
const MayoVariantParams = params_mod.MayoVariantParams;

pub const CodecError = error{
    InsufficientBytesForDecoding,
    IncorrectNumberOfElements, // For matrix construction
    AllocationFailed,
    Unimplemented, // Placeholder for functions not yet implemented
};

// --- GFElement Vector Encoding/Decoding (Re-implementing from previous subtask) ---

/// Encodes a vector of GF(16) elements into a byte array.
/// Each GFElement (u4) is packed into bytes. Two elements fit into one byte.
/// The first element of a pair is stored in the low nibble, the second in the high nibble.
pub fn encode_gf_elements(
    allocator: Allocator,
    elements: GFVector,
) !ArrayList(u8) {
    const num_elements = elements.items.len;
    const num_bytes = (num_elements + 1) / 2;

    var packed_bytes = ArrayList(u8).init(allocator);
    // errdefer if (packed_bytes.capacity > 0) packed_bytes.deinit(); // deinit only if owned and error after init

    if (num_bytes == 0) return packed_bytes; // Handle empty input gracefully

    try packed_bytes.ensureTotalCapacity(num_bytes);

    var i: usize = 0;
    while (i < num_elements) : (i += 2) {
        const el1 = elements.items[i];
        if (el1 > 15) @panic("GFElement out of range");

        if (i + 1 < num_elements) {
            const el2 = elements.items[i + 1];
            if (el2 > 15) @panic("GFElement out of range");
            try packed_bytes.append(@intCast(u8, el1 | (el2 << 4)));
        } else {
            try packed_bytes.append(@intCast(u8, el1));
        }
    }
    return packed_bytes;
}

/// Decodes a byte array into a vector of GF(16) elements.
pub fn decode_gf_elements(
    allocator: Allocator,
    bytes: []const u8,
    num_elements: usize,
) !GFVector {
    if (num_elements == 0) return GFVector.init(allocator);

    const expected_num_bytes = (num_elements + 1) / 2;
    if (bytes.len < expected_num_bytes) {
        return CodecError.InsufficientBytesForDecoding;
    }

    var decoded_elements = GFVector.init(allocator);
    // errdefer if (decoded_elements.capacity > 0) decoded_elements.deinit();

    try decoded_elements.ensureTotalCapacity(num_elements);

    var byte_idx: usize = 0;
    var elements_count: usize = 0;

    while (elements_count < num_elements) {
        if (byte_idx >= bytes.len) return CodecError.InsufficientBytesForDecoding;
        const current_byte = bytes[byte_idx];

        try decoded_elements.append(@intCast(GFElement, current_byte & 0x0F));
        elements_count += 1;

        if (elements_count == num_elements) break;

        try decoded_elements.append(@intCast(GFElement, (current_byte >> 4) & 0x0F));
        elements_count += 1;

        byte_idx += 1;
    }
    std.debug.assert(decoded_elements.items.len == num_elements);
    return decoded_elements;
}

// --- Matrix Decoding Functions ---

/// Helper for decoding upper triangular matrices.
/// Fills a (size x size) matrix from a list of (size*(size+1)/2) elements.
/// The elements are for the upper triangle (row by row). Lower triangle is filled by symmetry.
fn decode_upper_triangular_matrix(
    allocator: Allocator,
    elements_vec: *const GFVector, // Pointer to avoid consuming caller's vector
    size: usize,
) !GFMatrix {
    const expected_elements = size * (size + 1) / 2;
    if (elements_vec.items.len != expected_elements) {
        return CodecError.IncorrectNumberOfElements;
    }

    var matrix = try GFMatrix.init(allocator, size, size);
    errdefer matrix.deinit();

    var k: usize = 0; // Index for elements_vec
    for (0..size) |r| {
        for (r..size) |c| { // Iterate through upper triangle, r <= c
            if (k >= elements_vec.items.len) return CodecError.IncorrectNumberOfElements; // Should not happen if initial check is fine
            const val = elements_vec.items[k];
            try matrix.set(r, c, val);
            if (r != c) { // Fill symmetric element for non-diagonal
                try matrix.set(c, r, val);
            }
            k += 1;
        }
    }
    std.debug.assert(k == expected_elements); // All elements should have been consumed
    return matrix;
}

/// Decodes the O matrix from its byte representation. Matrix O is `(n-o) x o`.
pub fn decode_o_matrix(allocator: Allocator, o_bytes: []const u8, params: MayoVariantParams) !GFMatrix {
    const rows = params.n - params.o;
    const cols = params.o;
    const num_total_elements = rows * cols;

    var elements_vec = try decode_gf_elements(allocator, o_bytes, num_total_elements);
    defer elements_vec.deinit();

    if (elements_vec.items.len != num_total_elements) {
        // This should ideally be caught by decode_gf_elements if bytes.len is too short
        // or if num_elements implies more bytes than available.
        // However, an explicit check here for the count is good.
        return CodecError.IncorrectNumberOfElements;
    }
    
    var matrix = try GFMatrix.init(allocator, rows, cols);
    errdefer matrix.deinit();
    
    // Fill the matrix row by row (or column by column, standard is row-major for flat arrays)
    var k: usize = 0;
    for (0..rows) |r| {
        for (0..cols) |c| {
            try matrix.set(r, c, elements_vec.items[k]);
            k += 1;
        }
    }
    return matrix;
}


/// Decodes P1 matrices from byte representation.
/// P1 consists of `m` matrices, each P(1)i is `(n-o) x (n-o)` and upper triangular.
pub fn decode_p1_matrices(allocator: Allocator, p1_bytes: []const u8, params: MayoVariantParams) !std.ArrayList(GFMatrix) {
    var matrices = std.ArrayList(GFMatrix).init(allocator);
    errdefer {
        for (matrices.items) |mat| mat.deinit();
        matrices.deinit();
    }

    const N_vo = params.n - params.o;
    const elements_per_matrix = N_vo * (N_vo + 1) / 2;
    const bytes_per_matrix = (elements_per_matrix + 1) / 2;
    
    if (p1_bytes.len < params.m * bytes_per_matrix) {
        return CodecError.InsufficientBytesForDecoding;
    }

    var current_byte_offset: usize = 0;
    for (0..params.m) |_| {
        const slice_end = current_byte_offset + bytes_per_matrix;
        if (slice_end > p1_bytes.len) return CodecError.InsufficientBytesForDecoding; // Should be caught by initial check too
        
        const matrix_bytes = p1_bytes[current_byte_offset..slice_end];
        
        var elements_vec = try decode_gf_elements(allocator, matrix_bytes, elements_per_matrix);
        // decode_upper_triangular_matrix will take ownership of elements_vec's data if we pass by value
        // or it can take a pointer/slice. Let's pass pointer for clarity.
        var p1_i = try decode_upper_triangular_matrix(allocator, &elements_vec, N_vo);
        elements_vec.deinit(); // We are done with elements_vec for this matrix

        try matrices.append(p1_i);
        current_byte_offset += bytes_per_matrix;
    }
    return matrices;
}

/// Decodes P2 matrices from byte representation.
/// P2 consists of `m` matrices, each P(2)i is `(n-o) x o`. Dense.
pub fn decode_p2_matrices(allocator: Allocator, p2_bytes: []const u8, params: MayoVariantParams) !std.ArrayList(GFMatrix) {
    var matrices = std.ArrayList(GFMatrix).init(allocator);
     errdefer {
        for (matrices.items) |mat| mat.deinit();
        matrices.deinit();
    }

    const rows = params.n - params.o;
    const cols = params.o;
    const elements_per_matrix = rows * cols;
    const bytes_per_matrix = (elements_per_matrix + 1) / 2;

    if (p2_bytes.len < params.m * bytes_per_matrix) {
        return CodecError.InsufficientBytesForDecoding;
    }

    var current_byte_offset: usize = 0;
    for (0..params.m) |_| {
        const slice_end = current_byte_offset + bytes_per_matrix;
        if (slice_end > p2_bytes.len) return CodecError.InsufficientBytesForDecoding;

        const matrix_bytes = p2_bytes[current_byte_offset..slice_end];
        var elements_vec = try decode_gf_elements(allocator, matrix_bytes, elements_per_matrix);
        defer elements_vec.deinit(); // Defer here as it's used to build matrix directly

        var p2_i = try GFMatrix.init(allocator, rows, cols);
        // errdefer p2_i.deinit(); // This would deinit if append fails, handled by outer errdefer

        var k: usize = 0;
        for (0..rows) |r| {
            for (0..cols) |c| {
                try p2_i.set(r, c, elements_vec.items[k]);
                k += 1;
            }
        }
        try matrices.append(p2_i);
        current_byte_offset += bytes_per_matrix;
    }
    return matrices;
}

/// Decodes P3 matrices from byte representation.
/// P3 consists of `m` matrices, each P(3)i is `o x o` and upper triangular.
pub fn decode_p3_matrices(allocator: Allocator, p3_bytes: []const u8, params: MayoVariantParams) !std.ArrayList(GFMatrix) {
    var matrices = std.ArrayList(GFMatrix).init(allocator);
    errdefer {
        for (matrices.items) |mat| mat.deinit();
        matrices.deinit();
    }

    const O_size = params.o;
    const elements_per_matrix = O_size * (O_size + 1) / 2;
    const bytes_per_matrix = (elements_per_matrix + 1) / 2;

    if (p3_bytes.len < params.m * bytes_per_matrix) {
        return CodecError.InsufficientBytesForDecoding;
    }
    
    var current_byte_offset: usize = 0;
    for (0..params.m) |_| {
        const slice_end = current_byte_offset + bytes_per_matrix;
        if (slice_end > p3_bytes.len) return CodecError.InsufficientBytesForDecoding;

        const matrix_bytes = p3_bytes[current_byte_offset..slice_end];
        var elements_vec = try decode_gf_elements(allocator, matrix_bytes, elements_per_matrix);
        // defer elements_vec.deinit(); // elements_vec will be consumed by decode_upper_triangular_matrix

        var p3_i = try decode_upper_triangular_matrix(allocator, &elements_vec, O_size);
        elements_vec.deinit(); // Done with elements_vec

        try matrices.append(p3_i);
        current_byte_offset += bytes_per_matrix;
    }
    return matrices;
}

/// Decodes L matrices from byte representation. Li is (n-o) x o. Dense.
/// (Used in expanded secret key, structure similar to P2 matrices)
pub fn decode_l_matrices(allocator: Allocator, l_bytes: []const u8, params: MayoVariantParams) !std.ArrayList(GFMatrix) {
    // This is identical to decode_p2_matrices in structure, just different input bytes and semantic meaning
    var matrices = std.ArrayList(GFMatrix).init(allocator);
    errdefer {
        for (matrices.items) |mat| mat.deinit();
        matrices.deinit();
    }

    const rows = params.n - params.o;
    const cols = params.o;
    const elements_per_matrix = rows * cols;
    const bytes_per_matrix = (elements_per_matrix + 1) / 2;

    if (l_bytes.len < params.m * bytes_per_matrix) {
        return CodecError.InsufficientBytesForDecoding;
    }

    var current_byte_offset: usize = 0;
    for (0..params.m) |_| {
        const slice_end = current_byte_offset + bytes_per_matrix;
        if (slice_end > l_bytes.len) return CodecError.InsufficientBytesForDecoding;
        
        const matrix_bytes = l_bytes[current_byte_offset..slice_end];
        var elements_vec = try decode_gf_elements(allocator, matrix_bytes, elements_per_matrix);
        defer elements_vec.deinit();

        var l_i = try GFMatrix.init(allocator, rows, cols);
        // errdefer l_i.deinit();

        var k: usize = 0;
        for (0..rows) |r| {
            for (0..cols) |c| {
                try l_i.set(r, c, elements_vec.items[k]);
                k += 1;
            }
        }
        try matrices.append(l_i);
        current_byte_offset += bytes_per_matrix;
    }
    return matrices;
}

/// Encodes the solution vector `s` (a GFVector) into bytes. Length of s is params.n.
pub fn encode_s_vector(allocator: Allocator, s_vector: GFVector, params: MayoVariantParams) !std.ArrayList(u8) {
    if (s_vector.items.len != params.n) return CodecError.IncorrectNumberOfElements;
    return encode_gf_elements(allocator, s_vector);
}

/// Decodes the solution vector `s` (a GFVector) from bytes. Length of s is params.n.
pub fn decode_s_vector(allocator: Allocator, s_bytes: []const u8, params: MayoVariantParams) !GFVector {
    return decode_gf_elements(allocator, s_bytes, params.n);
}


// --- Unit Tests for GFElement Codecs (Re-adding) ---
fn make_gf_vector(allocator: Allocator, comptime values: []const u4) !GFVector {
    var vec = GFVector.init(allocator);
    // errdefer vec.deinit(); // Caller owns deinit if successful
    for (values) |v| {
        try vec.append(v);
    }
    return vec;
}

test "encode_gf_elements: basic" {
    const allocator = testing.allocator;
    var elements = try make_gf_vector(allocator, &.{ 3, 10, 7, 1 }); defer elements.deinit();
    var packed = try encode_gf_elements(allocator, elements); defer packed.deinit();
    try testing.expectEqualSlices(u8, &.{ 0xA3, 0x17 }, packed.items);

    var elements_odd = try make_gf_vector(allocator, &.{ 3, 10, 7 }); defer elements_odd.deinit();
    var packed_odd = try encode_gf_elements(allocator, elements_odd); defer packed_odd.deinit();
    try testing.expectEqualSlices(u8, &.{ 0xA3, 0x07 }, packed_odd.items);
}

test "decode_gf_elements: basic" {
    const allocator = testing.allocator;
    var decoded = try decode_gf_elements(allocator, &.{0xA3, 0x17}, 4); defer decoded.deinit();
    try testing.expectEqualSlices(GFElement, &.{3,10,7,1}, decoded.items);
    
    var decoded_odd = try decode_gf_elements(allocator, &.{0xA3, 0x07}, 3); defer decoded_odd.deinit();
    try testing.expectEqualSlices(GFElement, &.{3,10,7}, decoded_odd.items);
}

test "round trip: gf_elements" {
    const allocator = testing.allocator;
    var original = try make_gf_vector(allocator, &.{ 1, 2, 3, 15, 0, 5 }); defer original.deinit();
    var packed = try encode_gf_elements(allocator, original); defer packed.deinit();
    var decoded = try decode_gf_elements(allocator, packed.items, original.items.len); defer decoded.deinit();
    try testing.expectEqualSlices(GFElement, original.items, decoded.items);
}

// --- Unit Tests for Matrix Codecs ---

// Mock MayoVariantParams for testing. In real usage, these come from params_mod.get_params(variant).
fn get_test_params() MayoVariantParams {
    return MayoVariantParams {
        .name = "test_variant", .l = 0, // l not used by codec directly
        .n = 4, .m = 2, .o = 2, .k = 0, // n=4, o=2 => n-o = 2. m=2 matrices.
        .pk_seed_bytes = 0, .sk_seed_bytes = 0, .salt_bytes = 0, .m_digest_bytes = 0, 
        .p1_bytes = 0, .p2_bytes = 0, .p3_bytes = 0, .o_bytes = 0, .s_bytes = 0, .sig_salt_bytes = 0,
    };
}

test "decode_upper_triangular_matrix: basic 2x2" {
    const allocator = testing.allocator;
    // For 2x2 matrix, elements are M00, M01, M11 (3 elements)
    var elements = try make_gf_vector(allocator, &.{1,2,3}); defer elements.deinit();
    var matrix = try decode_upper_triangular_matrix(allocator, &elements, 2); defer matrix.deinit();

    try testing.expectEqual(@as(usize, 2), matrix.rows);
    try testing.expectEqual(@as(usize, 2), matrix.cols);
    try testing.expectEqual(@as(GFElement, 1), try matrix.get(0,0));
    try testing.expectEqual(@as(GFElement, 2), try matrix.get(0,1));
    try testing.expectEqual(@as(GFElement, 2), try matrix.get(1,0)); // Symmetric part
    try testing.expectEqual(@as(GFElement, 3), try matrix.get(1,1));
}

test "decode_upper_triangular_matrix: 3x3" {
    const allocator = testing.allocator;
    // 3x3 matrix needs 3*(3+1)/2 = 6 elements: M00,M01,M02, M11,M12, M22
    var elements = try make_gf_vector(allocator, &.{1,2,3, 4,5, 6}); defer elements.deinit();
    var matrix = try decode_upper_triangular_matrix(allocator, &elements, 3); defer matrix.deinit();
    
    try testing.expectEqual(@as(GFElement, 1), try matrix.get(0,0));
    try testing.expectEqual(@as(GFElement, 2), try matrix.get(0,1));
    try testing.expectEqual(@as(GFElement, 3), try matrix.get(0,2));
    try testing.expectEqual(@as(GFElement, 2), try matrix.get(1,0)); // Symm
    try testing.expectEqual(@as(GFElement, 4), try matrix.get(1,1));
    try testing.expectEqual(@as(GFElement, 5), try matrix.get(1,2));
    try testing.expectEqual(@as(GFElement, 3), try matrix.get(2,0)); // Symm
    try testing.expectEqual(@as(GFElement, 5), try matrix.get(2,1)); // Symm
    try testing.expectEqual(@as(GFElement, 6), try matrix.get(2,2));
}

test "decode_upper_triangular_matrix: error on wrong number of elements" {
    const allocator = testing.allocator;
    var elements_too_few = try make_gf_vector(allocator, &.{1,2}); defer elements_too_few.deinit(); // For 2x2, needs 3
    try testing.expectError(CodecError.IncorrectNumberOfElements, decode_upper_triangular_matrix(allocator, &elements_too_few, 2));

    var elements_too_many = try make_gf_vector(allocator, &.{1,2,3,4}); defer elements_too_many.deinit(); // For 2x2, needs 3
    try testing.expectError(CodecError.IncorrectNumberOfElements, decode_upper_triangular_matrix(allocator, &elements_too_many, 2));
}


test "decode_o_matrix: basic" {
    const allocator = testing.allocator;
    const params = get_test_params(); // n=4, o=2. So O is (4-2)x2 = 2x2. Needs 4 elements.
    const num_o_elements = (params.n - params.o) * params.o; // 2*2=4
    const o_bytes_len = (num_o_elements + 1) / 2; // (4+1)/2 = 2 bytes
    
    // Example: elements are [1,2,3,4]. Packed: 0x21, 0x43
    const o_bytes_data = [_]u8{0x21, 0x43};

    var matrix_o = try decode_o_matrix(allocator, &o_bytes_data, params);
    defer matrix_o.deinit();

    try testing.expectEqual(@as(usize, 2), matrix_o.rows);
    try testing.expectEqual(@as(usize, 2), matrix_o.cols);
    try testing.expectEqual(@as(GFElement, 1), try matrix_o.get(0,0));
    try testing.expectEqual(@as(GFElement, 2), try matrix_o.get(0,1));
    try testing.expectEqual(@as(GFElement, 3), try matrix_o.get(1,0));
    try testing.expectEqual(@as(GFElement, 4), try matrix_o.get(1,1));
}

test "decode_p1_matrices: basic" {
    const allocator = testing.allocator;
    const params = get_test_params(); // m=2. P1_i is (n-o)x(n-o) = 2x2 upper triangular. Needs 3 elements. (3+1)/2 = 2 bytes per matrix.
    const bytes_per_p1_matrix = ( ( (params.n-params.o) * (params.n-params.o+1)/2 ) + 1) / 2; // 2 bytes
    const total_p1_bytes = params.m * bytes_per_p1_matrix; // 2 * 2 = 4 bytes

    // P1_0 elements [1,2,3] -> 0x21, 0x03
    // P1_1 elements [4,5,6] -> 0x54, 0x06
    const p1_bytes_data = [_]u8{0x21, 0x03, 0x54, 0x06};
    
    var p1_mats = try decode_p1_matrices(allocator, &p1_bytes_data, params);
    defer {
        for (p1_mats.items) |m| m.deinit();
        p1_mats.deinit();
    }

    try testing.expectEqual(@as(usize, params.m), p1_mats.items.len);
    
    // Check P1_0
    const p1_0 = p1_mats.items[0];
    try testing.expectEqual(@as(usize, 2), p1_0.rows);
    try testing.expectEqual(@as(usize, 2), p1_0.cols);
    try testing.expectEqual(@as(GFElement, 1), try p1_0.get(0,0));
    try testing.expectEqual(@as(GFElement, 2), try p1_0.get(0,1));
    try testing.expectEqual(@as(GFElement, 3), try p1_0.get(1,1));
    try testing.expectEqual(@as(GFElement, 2), try p1_0.get(1,0)); // Symmetric part

    // Check P1_1
    const p1_1 = p1_mats.items[1];
    try testing.expectEqual(@as(GFElement, 4), try p1_1.get(0,0));
    try testing.expectEqual(@as(GFElement, 5), try p1_1.get(0,1));
    try testing.expectEqual(@as(GFElement, 6), try p1_1.get(1,1));
}

test "decode_p2_matrices: basic" {
    const allocator = testing.allocator;
    const params = get_test_params(); // m=2. P2_i is (n-o)xo = 2x2 dense. Needs 4 elements. (4+1)/2 = 2 bytes per matrix.
    const bytes_per_p2_matrix = ( ( (params.n-params.o) * params.o ) + 1) / 2; // 2 bytes
    const total_p2_bytes = params.m * bytes_per_p2_matrix; // 4 bytes

    // P2_0 elements [1,2,3,4] -> 0x21, 0x43
    // P2_1 elements [5,6,7,8] -> 0x65, 0x87
    const p2_bytes_data = [_]u8{0x21, 0x43, 0x65, 0x87};

    var p2_mats = try decode_p2_matrices(allocator, &p2_bytes_data, params);
    defer {
        for (p2_mats.items) |m| m.deinit();
        p2_mats.deinit();
    }
    try testing.expectEqual(@as(usize, params.m), p2_mats.items.len);

    // Check P2_0
    const p2_0 = p2_mats.items[0];
    try testing.expectEqual(@as(usize, 2), p2_0.rows);
    try testing.expectEqual(@as(usize, 2), p2_0.cols);
    try testing.expectEqual(@as(GFElement, 1), try p2_0.get(0,0));
    try testing.expectEqual(@as(GFElement, 2), try p2_0.get(0,1));
    try testing.expectEqual(@as(GFElement, 3), try p2_0.get(1,0));
    try testing.expectEqual(@as(GFElement, 4), try p2_0.get(1,1));
    
    // Check P2_1
    const p2_1 = p2_mats.items[1];
    try testing.expectEqual(@as(GFElement, 5), try p2_1.get(0,0));
    try testing.expectEqual(@as(GFElement, 6), try p2_1.get(0,1));
    try testing.expectEqual(@as(GFElement, 7), try p2_1.get(1,0));
    try testing.expectEqual(@as(GFElement, 8), try p2_1.get(1,1));
}

test "decode_p3_matrices: basic" {
    const allocator = testing.allocator;
    const params = get_test_params(); // m=2. P3_i is oxo = 2x2 upper triangular. Needs 3 elements. 2 bytes per matrix.
    const bytes_per_p3_matrix = ( ( params.o * (params.o+1)/2 ) + 1) / 2; // 2 bytes
    const total_p3_bytes = params.m * bytes_per_p3_matrix; // 4 bytes

    // P3_0 elements [1,2,3] -> 0x21, 0x03
    // P3_1 elements [4,5,6] -> 0x54, 0x06
    const p3_bytes_data = [_]u8{0x21, 0x03, 0x54, 0x06};
    
    var p3_mats = try decode_p3_matrices(allocator, &p3_bytes_data, params);
    defer {
        for (p3_mats.items) |m| m.deinit();
        p3_mats.deinit();
    }
    try testing.expectEqual(@as(usize, params.m), p3_mats.items.len);
    // Check P3_0 (similar to P1_0 in structure)
    const p3_0 = p3_mats.items[0];
    try testing.expectEqual(@as(GFElement, 1), try p3_0.get(0,0));
    try testing.expectEqual(@as(GFElement, 2), try p3_0.get(0,1));
    try testing.expectEqual(@as(GFElement, 3), try p3_0.get(1,1));
}

test "decode_l_matrices: basic" {
    // L matrices are (n-o) x o, dense. Same structure as P2.
    const allocator = testing.allocator;
    const params = get_test_params(); // m=2. L_i is (n-o)xo = 2x2 dense. Needs 4 elements. 2 bytes per matrix.
    const bytes_per_l_matrix = ( ( (params.n-params.o) * params.o ) + 1) / 2;
    const total_l_bytes = params.m * bytes_per_l_matrix;

    const l_bytes_data = [_]u8{0x21, 0x43, 0x65, 0x87}; // Same data as P2 test
    var l_mats = try decode_l_matrices(allocator, &l_bytes_data, params);
    defer {
        for (l_mats.items) |m| m.deinit();
        l_mats.deinit();
    }
    try testing.expectEqual(@as(usize, params.m), l_mats.items.len);
    const l_0 = l_mats.items[0];
    try testing.expectEqual(@as(GFElement, 1), try l_0.get(0,0)); // Check some values
    try testing.expectEqual(@as(GFElement, 4), try l_0.get(1,1));
}

test "decode_s_vector: basic" {
    const allocator = testing.allocator;
    const params = get_test_params(); // n=4. Needs 4 elements. (4+1)/2 = 2 bytes.
    const s_bytes_data = [_]u8{0x21, 0x43}; // Elements [1,2,3,4]

    var s_vec = try decode_s_vector(allocator, &s_bytes_data, params);
    defer s_vec.deinit();

    try testing.expectEqual(@as(usize, params.n), s_vec.items.len);
    try testing.expectEqualSlices(GFElement, &.{1,2,3,4}, s_vec.items);
}

test "encode_s_vector: basic" {
    const allocator = testing.allocator;
    const params = get_test_params(); // n=4
    var s_vec = try make_gf_vector(allocator, &.{1,2,3,4}); defer s_vec.deinit();
    
    var s_bytes = try encode_s_vector(allocator, s_vec, params);
    defer s_bytes.deinit();
    
    try testing.expectEqualSlices(u8, &.{0x21, 0x43}, s_bytes.items);
}

test "decode_*: insufficient bytes error" {
    const allocator = testing.allocator;
    const params = get_test_params();
    const few_bytes = [_]u8{0x01}; // Not enough for most structures here

    try testing.expectError(CodecError.InsufficientBytesForDecoding, decode_o_matrix(allocator, &few_bytes, params));
    try testing.expectError(CodecError.InsufficientBytesForDecoding, decode_p1_matrices(allocator, &few_bytes, params));
    try testing.expectError(CodecError.InsufficientBytesForDecoding, decode_p2_matrices(allocator, &few_bytes, params));
    try testing.expectError(CodecError.InsufficientBytesForDecoding, decode_p3_matrices(allocator, &few_bytes, params));
    try testing.expectError(CodecError.InsufficientBytesForDecoding, decode_l_matrices(allocator, &few_bytes, params));
    try testing.expectError(CodecError.InsufficientBytesForDecoding, decode_s_vector(allocator, &few_bytes, params));
}

```
