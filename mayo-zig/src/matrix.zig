// mayo-zig/src/matrix.zig

//! Implements matrix operations over GF(16).

const std = @import("std");
const types = @import("types.zig");
const gf = @import("gf.zig");

const Allocator = std.mem.Allocator;
const GFElement = types.GFElement;
const GFVector = types.GFVector;
const GFMatrix = types.GFMatrix;

// --- Implementation of GFMatrix helper functions ---
// GFMatrix struct is in types.zig. We add more functions that operate on or produce GFMatrix.

/// Creates a new matrix from a flat slice of data, rows, and columns.
/// Returns error if data.len != rows * cols.
pub fn new_matrix_with_data(allocator: Allocator, rows: usize, cols: usize, data: []const GFElement) !GFMatrix {
    if (data.len != rows * cols) {
        return error.MatrixDimensionMismatch;
    }
    var matrix = try GFMatrix.new(allocator, rows, cols);
    errdefer matrix.deinit();
    std.mem.copy(GFElement, matrix.data.items, data);
    return matrix;
}

/// Creates a new matrix filled with GFElement(0).
/// types.GFMatrix.new already does this. This is an explicit alias.
pub fn zero_matrix(allocator: Allocator, rows: usize, cols: usize) !GFMatrix {
    return GFMatrix.new(allocator, rows, cols);
}

/// Creates an identity matrix of a given size.
pub fn identity_matrix(allocator: Allocator, size: usize) !GFMatrix {
    var matrix = try zero_matrix(allocator, size, size);
    errdefer matrix.deinit(); // Ensure cleanup if set fails, though set doesn't error here
    for (0..size) |i| {
        matrix.set(i, i, GFElement.new(1)); // GF(16) one
    }
    return matrix;
}

// Note: get_opt, get_unsafe, set_val, num_rows, num_cols, to_vectors, from_vectors
// are already part of or can be easily added to types.GFMatrix if desired.
// For this port, we'll keep matrix operations separate if they are standalone functions in Rust.
// get_unsafe is essentially matrix.data.items[r * matrix.cols + c] with manual bounds check.
// set_val is matrix.data.items[r * matrix.cols + c] = val with manual bounds check.

// --- Standalone Matrix Operations ---

/// Adds two matrices over GF(16).
/// Returns error if dimensions are incompatible.
pub fn matrix_add(allocator: Allocator, a: GFMatrix, b: GFMatrix) !GFMatrix {
    if (a.num_rows() != b.num_rows() or a.num_cols() != b.num_cols()) {
        return error.MatrixDimensionMismatch;
    }
    var result_matrix = try GFMatrix.new(allocator, a.num_rows(), a.num_cols());
    errdefer result_matrix.deinit();

    for (a.data.items, b.data.items, 0..) |a_val, b_val, i| {
        result_matrix.data.items[i] = gf.gf16_add(a_val, b_val);
    }
    return result_matrix;
}

/// Subtracts matrix b from matrix a over GF(16).
/// (Identical to addition in GF(2^n)).
pub fn matrix_sub(allocator: Allocator, a: GFMatrix, b: GFMatrix) !GFMatrix {
    return matrix_add(allocator, a, b); // In GF(2^n), subtraction is XOR, same as addition
}

/// Multiplies each element of a matrix by a scalar in GF(16).
pub fn matrix_scalar_mul(allocator: Allocator, scalar: GFElement, matrix: GFMatrix) !GFMatrix {
    var result_matrix = try GFMatrix.new(allocator, matrix.num_rows(), matrix.num_cols());
    errdefer result_matrix.deinit();
    for (matrix.data.items, 0..) |val, i| {
        result_matrix.data.items[i] = gf.gf16_mul(scalar, val);
    }
    return result_matrix;
}

/// Multiplies two matrices (a * b) over GF(16).
/// Returns error if dimensions are incompatible (a.cols != b.rows).
pub fn matrix_mul(allocator: Allocator, a: GFMatrix, b: GFMatrix) !GFMatrix {
    if (a.num_cols() != b.num_rows()) {
        return error.MatrixDimensionMismatch;
    }
    const result_rows = a.num_rows();
    const result_cols = b.num_cols();
    var result_matrix = try zero_matrix(allocator, result_rows, result_cols);
    errdefer result_matrix.deinit();

    for (0..result_rows) |r| {
        for (0..result_cols) |c| {
            var sum = GFElement.new(0);
            for (0..a.num_cols()) |k_idx| { // a.num_cols() or b.num_rows()
                const val_a = a.get(r, k_idx).?; // Assuming get returns non-null due to logic
                const val_b = b.get(k_idx, c).?;
                sum = gf.gf16_add(sum, gf.gf16_mul(val_a, val_b));
            }
            result_matrix.set(r, c, sum);
        }
    }
    return result_matrix;
}

/// Transposes a matrix over GF(16).
pub fn matrix_transpose(allocator: Allocator, matrix: GFMatrix) !GFMatrix {
    var transposed_matrix = try zero_matrix(allocator, matrix.num_cols(), matrix.num_rows());
    errdefer transposed_matrix.deinit();
    for (0..matrix.num_rows()) |r| {
        for (0..matrix.num_cols()) |c| {
            transposed_matrix.set(c, r, matrix.get(r, c).?);
        }
    }
    return transposed_matrix;
}

/// Multiplies a matrix by a vector (matrix * vector) over GF(16).
/// Treats the vector as a column vector.
/// Returns error if dimensions are incompatible (matrix.cols != vector.len()).
pub fn matrix_vec_mul(allocator: Allocator, matrix: GFMatrix, vector: GFVector) !GFVector {
    if (matrix.num_cols() != vector.items.len) {
        return error.MatrixDimensionMismatch;
    }
    var result_vector = GFVector.init(allocator);
    errdefer result_vector.deinit();
    try result_vector.ensureTotalCapacity(matrix.num_rows());

    for (0..matrix.num_rows()) |r| {
        var sum = GFElement.new(0);
        for (0..matrix.num_cols()) |c| {
            sum = gf.gf16_add(sum, gf.gf16_mul(matrix.get(r, c).?, vector.items[c]));
        }
        result_vector.appendAssumeCapacity(sum);
    }
    return result_vector;
}

/// Subtracts vector `b` from vector `a` over GF(16) (element-wise).
/// Returns error if dimensions are incompatible.
pub fn vector_sub(allocator: Allocator, a: GFVector, b: GFVector) !GFVector {
    if (a.items.len != b.items.len) {
        return error.VectorDimensionMismatch;
    }
    var result = GFVector.init(allocator);
    errdefer result.deinit();
    try result.ensureTotalCapacity(a.items.len);

    for (a.items, b.items) |a_val, b_val| {
        result.appendAssumeCapacity(gf.gf16_sub(a_val, b_val)); // gf16_sub is XOR
    }
    return result;
}

/// Symmetrizes a square matrix M by computing M + M^T.
pub fn matrix_symmetrize(allocator: Allocator, matrix: GFMatrix) !GFMatrix {
    if (matrix.num_rows() != matrix.num_cols()) {
        return error.MatrixNotSquare;
    }
    const n = matrix.num_rows();
    var sym_matrix = try zero_matrix(allocator, n, n);
    errdefer sym_matrix.deinit();
    for (0..n) |r| {
        for (0..n) |c| {
            const val = gf.gf16_add(matrix.get(r,c).?, matrix.get(c,r).?);
            sym_matrix.set(r,c, val);
        }
    }
    return sym_matrix;
}

/// Multiplies a row vector (GFVector) by a matrix: v * M.
/// vector_lhs is N elements. matrix_rhs is NxK. Result is K elements (GFVector).
pub fn vec_matrix_mul(allocator: Allocator, vector_lhs: GFVector, matrix_rhs: GFMatrix) !GFVector {
    if (vector_lhs.items.len != matrix_rhs.num_rows()) {
        return error.MatrixDimensionMismatch;
    }
    const num_cols_result = matrix_rhs.num_cols();
    var result_vector = GFVector.init(allocator);
    errdefer result_vector.deinit();
    try result_vector.ensureTotalCapacity(num_cols_result);

    for (0..num_cols_result) |c_res| { // For each column in the result vector
        var sum = GFElement.new(0);
        for (0..matrix_rhs.num_rows()) |r_m_idx| { // Summing down the column of matrix_rhs, weighted by vector_lhs
            sum = gf.gf16_add(sum, gf.gf16_mul(vector_lhs.items[r_m_idx], matrix_rhs.get(r_m_idx, c_res).?));
        }
        result_vector.appendAssumeCapacity(sum);
    }
    return result_vector;
}

/// Computes the dot product of two vectors: a . b.
pub fn vector_dot_product(a: GFVector, b: GFVector) !GFElement {
    if (a.items.len != b.items.len) {
        return error.VectorDimensionMismatch;
    }
    if (a.items.len == 0) {
        return GFElement.new(0);
    }
    var sum = GFElement.new(0);
    for (a.items, b.items) |a_val, b_val| {
        sum = gf.gf16_add(sum, gf.gf16_mul(a_val, b_val));
    }
    return sum;
}


// --- Unit Tests ---
const testing = std.testing;
const allocator = testing.allocator; // Use testing allocator for tests

fn gf_el(val: u8) GFElement { return GFElement.new(val); }

fn vec_gf_from_slice(slice: []const u8) !GFVector {
    var vec = GFVector.init(allocator);
    errdefer vec.deinit();
    for (slice) |item| {
        try vec.append(gf_el(item));
    }
    return vec;
}

fn matrix_from_slices(rows: usize, cols: usize, data_slices: []const []const u8) !GFMatrix {
    var flat_data = GFVector.init(allocator);
    defer flat_data.deinit();
    for (data_slices) |row_slice| {
        for (row_slice) |item| {
            try flat_data.append(gf_el(item));
        }
    }
    return new_matrix_with_data(allocator, rows, cols, flat_data.items);
}

test "matrix_symmetrize" {
    var u_matrix = try matrix_from_slices(3,3, &[_][]const u8{
        &[_]u8{1,2,3},
        &[_]u8{0,4,5},
        &[_]u8{0,0,6},
    });
    defer u_matrix.deinit();
    
    var s_matrix = try matrix_symmetrize(allocator, u_matrix);
    defer s_matrix.deinit();

    var expected_s_matrix = try matrix_from_slices(3,3, &[_][]const u8{
        &[_]u8{0,2,3},
        &[_]u8{2,0,5},
        &[_]u8{3,5,0},
    });
    defer expected_s_matrix.deinit();
    try testing.expectEqualSlices(GFElement, expected_s_matrix.data.items, s_matrix.data.items);

    var non_square = try zero_matrix(allocator, 2,3);
    defer non_square.deinit();
    try testing.expectError(error.MatrixNotSquare, matrix_symmetrize(allocator, non_square));
}

test "vec_matrix_mul (v^T * M in Rust)" {
    var v = try vec_gf_from_slice(&[_]u8{1,2,3}); // 1x3
    defer v.deinit();
    var m = try matrix_from_slices(3,2, &[_][]const u8{ // 3x2
        &[_]u8{1,4}, &[_]u8{2,5}, &[_]u8{3,6},
    });
    defer m.deinit();
    
    var result_vec = try vec_matrix_mul(allocator, v, m); // 1x2
    defer result_vec.deinit();

    // (1*1 + 2*2 + 3*3) = 1^4^5 = 0.
    // (1*4 + 2*5 + 3*6) = 4 ^ A ^ 2 = C.
    var corrected_expected_vec = try vec_gf_from_slice(&[_]u8{0, 12});
    defer corrected_expected_vec.deinit();
    try testing.expectEqualSlices(GFElement, corrected_expected_vec.items, result_vec.items);


    var v_short = try vec_gf_from_slice(&[_]u8{1,2});
    defer v_short.deinit();
    try testing.expectError(error.MatrixDimensionMismatch, vec_matrix_mul(allocator, v_short, m));
}

test "vector_dot_product" {
    var v1 = try vec_gf_from_slice(&[_]u8{1,2,3});
    defer v1.deinit();
    var v2 = try vec_gf_from_slice(&[_]u8{4,5,6});
    defer v2.deinit();
    // 1*4 + 2*5 + 3*6 = 4 ^ A ^ 2 = C (12)
    try testing.expectEqual(gf_el(12), try vector_dot_product(v1, v2));
    
    var v_empty1 = try vec_gf_from_slice(&[_]u8{});
    defer v_empty1.deinit();
    var v_empty2 = try vec_gf_from_slice(&[_]u8{});
    defer v_empty2.deinit();
    try testing.expectEqual(gf_el(0), try vector_dot_product(v_empty1, v_empty2));

    var v_short = try vec_gf_from_slice(&[_]u8{1});
    defer v_short.deinit();
    try testing.expectError(error.VectorDimensionMismatch, vector_dot_product(v1, v_short));
}

test "matrix constructors and getters" {
    var m1_data_slice = [_]GFElement{gf_el(1), gf_el(2), gf_el(3), gf_el(4)};
    var m1 = try new_matrix_with_data(allocator, 2, 2, &m1_data_slice);
    defer m1.deinit();
    try testing.expectEqual(@as(usize, 2), m1.num_rows());
    try testing.expectEqual(@as(usize, 2), m1.num_cols());
    try testing.expectEqual(gf_el(1), m1.get(0,0).?);
    try testing.expectEqual(gf_el(4), m1.get(1,1).?);

    var m_zero = try zero_matrix(allocator, 2, 3);
    defer m_zero.deinit();
    try testing.expectEqual(gf_el(0), m_zero.get(1,2).?);

    var m_id = try identity_matrix(allocator, 3);
    defer m_id.deinit();
    try testing.expectEqual(gf_el(1), m_id.get(0,0).?);
    try testing.expectEqual(gf_el(0), m_id.get(0,1).?);
}

test "matrix_add_sub" {
    var m1 = try matrix_from_slices(2,2, &[_][]const u8{&[_]u8{1,2},&[_]u8{3,4}});
    defer m1.deinit();
    var m2 = try matrix_from_slices(2,2, &[_][]const u8{&[_]u8{5,6},&[_]u8{7,8}});
    defer m2.deinit();
    var expected_sum = try matrix_from_slices(2,2, &[_][]const u8{&[_]u8{4,4},&[_]u8{4,12}});
    defer expected_sum.deinit();
    
    var sum_m = try matrix_add(allocator, m1, m2);
    defer sum_m.deinit();
    try testing.expectEqualSlices(GFElement, expected_sum.data.items, sum_m.data.items);
    
    var sub_m = try matrix_sub(allocator, m1, m2);
    defer sub_m.deinit();
    try testing.expectEqualSlices(GFElement, expected_sum.data.items, sub_m.data.items);

    var m3 = try zero_matrix(allocator,1,2);
    defer m3.deinit();
    try testing.expectError(error.MatrixDimensionMismatch, matrix_add(allocator, m1, m3));
}

test "matrix_scalar_mul" {
    var m = try matrix_from_slices(2,2, &[_][]const u8{&[_]u8{1,2},&[_]u8{3,0x8}});
    defer m.deinit();
    const scalar = gf_el(0x2);
    var expected = try matrix_from_slices(2,2, &[_][]const u8{&[_]u8{2,4},&[_]u8{6,3}});
    defer expected.deinit();
    
    var res_m = try matrix_scalar_mul(allocator, scalar, m);
    defer res_m.deinit();
    try testing.expectEqualSlices(GFElement, expected.data.items, res_m.data.items);
}

test "matrix_mul" {
    var a = try matrix_from_slices(2,2, &[_][]const u8{&[_]u8{1,2},&[_]u8{3,4}});
    defer a.deinit();
    var b = try matrix_from_slices(2,2, &[_][]const u8{&[_]u8{5,6},&[_]u8{7,1}});
    defer b.deinit();
    var expected = try matrix_from_slices(2,2, &[_][]const u8{&[_]u8{0xB,0x4},&[_]u8{0x0,0xE}});
    defer expected.deinit();

    var res_m = try matrix_mul(allocator, a, b);
    defer res_m.deinit();
    try testing.expectEqualSlices(GFElement, expected.data.items, res_m.data.items);

    var m_id = try identity_matrix(allocator, 2);
    defer m_id.deinit();
    var res_m_id = try matrix_mul(allocator, a, m_id);
    defer res_m_id.deinit();
    try testing.expectEqualSlices(GFElement, a.data.items, res_m_id.data.items);
}

test "matrix_transpose" {
     var m = try matrix_from_slices(2,3, &[_][]const u8{&[_]u8{1,2,3},&[_]u8{4,5,6}});
     defer m.deinit();
     var mt = try matrix_transpose(allocator, m);
     defer mt.deinit();
     try testing.expectEqual(@as(usize,3), mt.num_rows());
     try testing.expectEqual(@as(usize,2), mt.num_cols());
     try testing.expectEqual(gf_el(2), mt.get(1,0).?);
     try testing.expectEqual(gf_el(4), mt.get(0,1).?);
}

test "matrix_vec_mul (M * v)" {
    var matrix = try matrix_from_slices(2,3, &[_][]const u8{
        &[_]u8{1,2,3}, &[_]u8{4,5,6}
    });
    defer matrix.deinit();
    var vector = try vec_gf_from_slice(&[_]u8{1,2,3});
    defer vector.deinit();
    
    var res_vec = try matrix_vec_mul(allocator, matrix, vector);
    defer res_vec.deinit();
    // r0 = 1*1 + 2*2 + 3*3 = 1+4+5 = 0
    // r1 = 4*1 + 5*2 + 6*3 = 4+A+A = 4
    var expected_vec = try vec_gf_from_slice(&[_]u8{0,4});
    defer expected_vec.deinit();
    try testing.expectEqualSlices(GFElement, expected_vec.items, res_vec.items);
}

test "vector_sub" {
    var v1 = try vec_gf_from_slice(&[_]u8{5,6,7});
    defer v1.deinit();
    var v2 = try vec_gf_from_slice(&[_]u8{1,2,3});
    defer v2.deinit();
    var expected = try vec_gf_from_slice(&[_]u8{4,4,4});
    defer expected.deinit();
    var res_vec = try vector_sub(allocator, v1, v2);
    defer res_vec.deinit();
    try testing.expectEqualSlices(GFElement, expected.items, res_vec.items);
}
