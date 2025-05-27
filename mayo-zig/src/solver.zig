// mayo-zig/src/solver.zig

const std = @import("std");
const testing = std.testing;
const mem = std.mem;
const types = @import("types.zig");
const gf = @import("gf.zig");
const matrix_mod = @import("matrix.zig");

const Allocator = std.mem.Allocator;
const GFElement = types.GFElement;
const GFVector = types.GFVector;
const GFMatrix = types.GFMatrix;

pub const SolverError = error{
    MatrixDimensionMismatch,
    InternalMatrixError, // For errors from matrix operations
    DivisionByZero, // From gf.gf16_inv
    AllocationFailed,
    Unimplemented, // If any part remains
};

/// Solves a system of linear equations Ax = y over GF(16).
/// 'a_matrix' is an (m_eqs x o_vars) matrix.
/// 'y_vector' is a target vector of m_eqs elements.
/// Returns `Ok(Some(solution_x))` where `solution_x` is a vector of `o_vars` elements if a unique solution is found.
/// Returns `Ok(None)` if no solution or multiple solutions exist.
/// Returns an error for dimension mismatches or other issues.
pub fn solve_linear_system(
    allocator: Allocator,
    a_matrix: GFMatrix,
    y_vector: GFVector,
) !?GFVector {
    const m_eqs = a_matrix.num_rows();
    const o_vars = a_matrix.num_cols();

    if (m_eqs != y_vector.items.len) {
        return SolverError.MatrixDimensionMismatch;
    }
    if (m_eqs == 0) { // No equations
        if (o_vars == 0) return GFVector.init(allocator); // 0 equations, 0 variables, trivial solution
        return null; // 0 equations, some variables, infinite solutions
    }
    if (o_vars == 0) { // No variables
        // Check if y_vector is all zeros
        for (y_vector.items) |y_val| {
            if (y_val.as_int() != 0) return null; // 0 = non-zero, inconsistent
        }
        return GFVector.init(allocator); // 0 = 0, trivial solution (empty x vector)
    }

    // 2. Form augmented matrix [A | y].
    var aug_matrix = try GFMatrix.init(allocator, m_eqs, o_vars + 1);
    defer aug_matrix.deinit();

    // Copy A
    for (0..m_eqs) |r| {
        for (0..o_vars) |c| {
            try aug_matrix.set(r, c, try a_matrix.get(r, c));
        }
    }
    // Copy y
    for (0..m_eqs) |r| {
        try aug_matrix.set(r, o_vars, y_vector.items[r]);
    }

    // 3. Forward Elimination
    var pivot_row: usize = 0;
    var pivot_col: usize = 0;
    while (pivot_row < m_eqs and pivot_col < o_vars) {
        // a. Pivoting
        var max_row = pivot_row;
        var max_val = try aug_matrix.get(pivot_row, pivot_col); // Using the raw int value for comparison convenience
        
        // Find best pivot (can be any non-zero, first is fine)
        var r = pivot_row + 1;
        while (r < m_eqs) : (r += 1) {
            const current_val = try aug_matrix.get(r, pivot_col);
            if (current_val.as_int() != 0) { // Found a non-zero pivot candidate
                max_row = r;
                max_val = current_val;
                break; 
            }
        }
        
        if (max_val.as_int() == 0) { // If still zero after checking current row, try to find any non-zero
             var r_search = pivot_row;
             while(r_search < m_eqs) : (r_search += 1) {
                if((try aug_matrix.get(r_search, pivot_col)).as_int() != 0) {
                    max_row = r_search;
                    max_val = try aug_matrix.get(r_search, pivot_col);
                    break;
                }
             }
        }


        if (max_val.as_int() == 0) {
            // No pivot in this column, move to next column
            pivot_col += 1;
            continue;
        }

        // Swap pivot_row with max_row
        if (max_row != pivot_row) {
            try aug_matrix.swap_rows(pivot_row, max_row);
        }
        
        // b. Normalize Pivot Row
        const pivot_element = try aug_matrix.get(pivot_row, pivot_col);
        // std.debug.assert(pivot_element.as_int() != 0); // Should be true due to pivoting logic
        const inv_pivot = try gf.gf16_inv(pivot_element); // Can return error.DivisionByZero

        for (0..(o_vars + 1)) |c_idx| {
            const val = try aug_matrix.get(pivot_row, c_idx);
            try aug_matrix.set(pivot_row, c_idx, gf.gf16_mul(val, inv_pivot));
        }

        // c. Eliminate Other Rows
        for (0..m_eqs) |r_idx| {
            if (r_idx == pivot_row) continue;
            const factor = try aug_matrix.get(r_idx, pivot_col);
            if (factor.as_int() == 0) continue;

            for (pivot_col..(o_vars + 1)) |c_idx| { // Start from pivot_col, elements before are zero
                const val_pivot_row = try aug_matrix.get(pivot_row, c_idx);
                const val_curr_row = try aug_matrix.get(r_idx, c_idx);
                const term_to_sub = gf.gf16_mul(factor, val_pivot_row);
                try aug_matrix.set(r_idx, c_idx, gf.gf16_sub(val_curr_row, term_to_sub));
            }
        }
        pivot_row += 1;
        pivot_col += 1;
    }

    // 4. Check for Inconsistency and Rank
    var rank: usize = 0;
    for (0..m_eqs) |r_idx| {
        var lhs_all_zero = true;
        for (0..o_vars) |c_idx| {
            if ((try aug_matrix.get(r_idx, c_idx)).as_int() != 0) {
                lhs_all_zero = false;
                break;
            }
        }
        if (lhs_all_zero) {
            if ((try aug_matrix.get(r_idx, o_vars)).as_int() != 0) {
                return null; // Inconsistent system: 0 = non-zero
            }
        } else {
            rank += 1; // This row contributes to the rank
        }
    }
    
    if (rank < o_vars) {
        return null; // Not a unique solution (rank < number of variables)
    }

    // 5. Back Substitution
    var solution_list = try ArrayList(GFElement).initCapacity(allocator, o_vars);
    errdefer solution_list.deinit();
    try solution_list.resize(o_vars); // Initialize with some value, will be overwritten

    var i: usize = o_vars;
    while(i > 0) : (i -=1) {
        const r_idx = i-1; // row index in RRE form (effectively)
                           // We need to find the pivot column for this row.
                           // In RRE form from this GE, row r_idx should have pivot at column r_idx if rank == o_vars.
        if (r_idx >= m_eqs) { // More variables than equations, or rank deficiency handled earlier
            // This case should be caught by rank < o_vars if it means free variables
            // If we are here, rank == o_vars, so m_eqs >= o_vars.
            // The value for x[r_idx] is in the augmented column of the r_idx-th pivot row.
            // After forward elimination, the matrix isn't strictly RRE if m_eqs > o_vars,
            // but the first `o_vars` rows (if rank is `o_vars`) contain the solution part.
             continue;
        }

        var val_x = try aug_matrix.get(r_idx, o_vars);
        var c_idx: usize = r_idx + 1;
        while(c_idx < o_vars) : (c_idx += 1) {
            const term_coeff = try aug_matrix.get(r_idx, c_idx);
            const term_val = solution_list.items[c_idx]; // x[c_idx]
            val_x = gf.gf16_sub(val_x, gf.gf16_mul(term_coeff, term_val));
        }
        solution_list.items[r_idx] = val_x;
    }
    
    // Wrap ArrayList in GFVector
    var sol_vec = GFVector.init(allocator);
    // errdefer sol_vec.deinit(); // Not here, ownership passed on success
    sol_vec.items = solution_list.toOwnedSlice(); // ArrayList gives up ownership
    sol_vec.capacity = solution_list.capacity;   // This might be tricky with toOwnedSlice.
                                               // Better: copy items.

    // Let's re-do the final solution vector creation carefully.
    solution_list.shrinkToFit(); // Optional
    var final_solution_vec = GFVector {
        .items = try solution_list.toOwnedSlice(), // ArrayList gives up ownership of buffer
        .capacity = solution_list.capacity,      // This is now 0 for solution_list
        .allocator = allocator,                  // GFVector needs allocator to own the slice
    };
    // Ensure solution_list itself doesn't try to deinit the buffer now owned by final_solution_vec
    solution_list.items = &.{}; // Clear items from list after toOwnedSlice


    return final_solution_vec;
}


// --- Unit Tests ---
fn assert_solution_equals(sol: ?GFVector, expected_raw: []const u4, allocator: Allocator) !void {
    if (sol) |s| {
        defer s.deinit();
        var expected_vec = try GFVector.initCapacity(allocator, expected_raw.len);
        defer expected_vec.deinit();
        for (expected_raw) |val_raw| {
            try expected_vec.append(GFElement.new(val_raw));
        }
        try testing.expectEqualSlices(GFElement, expected_vec.items, s.items);
    } else {
        try testing.expect(expected_raw.len == 0); // Convention for null solution if expected_raw is empty
    }
}

test "solve_linear_system: 2x2 unique solution" {
    const allocator = testing.allocator;
    // A = [[1,1], [1,2]]
    // y = [3, 5]
    // Solution: x = [1,2]
    // 1*x0 + 1*x1 = 3
    // 1*x0 + 2*x1 = 5
    // R2 - R1 => [0,1 | 2] => x1 = 2
    // R1 - R2' => [1,0 | 1] => x0 = 1
    var a_mat = try GFMatrix.init(allocator, 2, 2); defer a_mat.deinit();
    try a_mat.set(0,0, gf.one); try a_mat.set(0,1, gf.one);
    try a_mat.set(1,0, gf.one); try a_mat.set(1,1, GFElement.new(2));

    var y_vec = try GFVector.init_slice_copy(allocator, &.{GFElement.new(3), GFElement.new(5)});
    defer y_vec.deinit();

    var sol = try solve_linear_system(allocator, a_mat, y_vec);
    try assert_solution_equals(sol, &.{1,2}, allocator);
}

test "solve_linear_system: 3x3 unique solution" {
    const allocator = testing.allocator;
    // A = [[2,3,1], [1,1,1], [3,2,1]]
    // y = [1,0,1]
    // Using an online GF(16) calculator with polynomial x^4+x+1 (same as our gf.zig)
    // x0=1, x1=1, x2=0
    // 2*1 + 3*1 + 1*0 = 5 (Oops, example needs to be correct over GF(16))
    // Let A = [[1,1,1], [0,1,1], [0,0,1]] (already upper triangular)
    // y = [3,2,1]
    // x2 = 1
    // x1 + x2 = 2 => x1 + 1 = 2 => x1 = 3
    // x0 + x1 + x2 = 3 => x0 + 3 + 1 = 3 => x0 + 2 = 3 => x0 = 1
    // Solution: x = [1,3,1]
    var a_mat = try GFMatrix.init(allocator, 3, 3); defer a_mat.deinit();
    try a_mat.set(0,0, gf.one); try a_mat.set(0,1, gf.one); try a_mat.set(0,2, gf.one);
    try a_mat.set(1,0, gf.zero); try a_mat.set(1,1, gf.one); try a_mat.set(1,2, gf.one);
    try a_mat.set(2,0, gf.zero); try a_mat.set(2,1, gf.zero); try a_mat.set(2,2, gf.one);

    var y_vec = try GFVector.init_slice_copy(allocator, &.{GFElement.new(3), GFElement.new(2), GFElement.new(1)});
    defer y_vec.deinit();

    var sol = try solve_linear_system(allocator, a_mat, y_vec);
    try assert_solution_equals(sol, &.{1,3,1}, allocator);
}


test "solve_linear_system: inconsistent system (no solution)" {
    const allocator = testing.allocator;
    // A = [[1,1], [1,1]]
    // y = [1, 2]
    // x0 + x1 = 1
    // x0 + x1 = 2  => inconsistent
    var a_mat = try GFMatrix.init(allocator, 2, 2); defer a_mat.deinit();
    try a_mat.set(0,0, gf.one); try a_mat.set(0,1, gf.one);
    try a_mat.set(1,0, gf.one); try a_mat.set(1,1, gf.one);

    var y_vec = try GFVector.init_slice_copy(allocator, &.{GFElement.new(1), GFElement.new(2)});
    defer y_vec.deinit();

    var sol = try solve_linear_system(allocator, a_mat, y_vec);
    try testing.expect(sol == null);
}

test "solve_linear_system: multiple solutions (underdetermined)" {
    const allocator = testing.allocator;
    // A = [[1,1]]
    // y = [1]
    // x0 + x1 = 1. Many solutions (e.g. x0=1,x1=0 or x0=0,x1=1)
    // Solver should return null as it's not a unique solution.
    var a_mat = try GFMatrix.init(allocator, 1, 2); defer a_mat.deinit();
    try a_mat.set(0,0, gf.one); try a_mat.set(0,1, gf.one);

    var y_vec = try GFVector.init_slice_copy(allocator, &.{GFElement.new(1)});
    defer y_vec.deinit();
    
    var sol = try solve_linear_system(allocator, a_mat, y_vec);
    try testing.expect(sol == null); // Expect null due to non-unique solution
}

test "solve_linear_system: more equations than variables (consistent, unique)" {
    const allocator = testing.allocator;
    // A = [[1,0], [0,1], [1,1]] (3x2)
    // y = [1,2,3]
    // x0 = 1
    // x1 = 2
    // x0+x1 = 1+2 = 3. Consistent. Solution x=[1,2]
    var a_mat = try GFMatrix.init(allocator, 3, 2); defer a_mat.deinit();
    try a_mat.set(0,0, gf.one); try a_mat.set(0,1, gf.zero);
    try a_mat.set(1,0, gf.zero); try a_mat.set(1,1, gf.one);
    try a_mat.set(2,0, gf.one); try a_mat.set(2,1, gf.one);

    var y_vec = try GFVector.init_slice_copy(allocator, &.{GFElement.new(1), GFElement.new(2), GFElement.new(3)});
    defer y_vec.deinit();

    var sol = try solve_linear_system(allocator, a_mat, y_vec);
    try assert_solution_equals(sol, &.{1,2}, allocator);
}

test "solve_linear_system: more equations than variables (inconsistent)" {
    const allocator = testing.allocator;
    // A = [[1,0], [0,1], [1,1]] (3x2)
    // y = [1,2,4] // Last equation x0+x1 = 4, but 1+2=3. Inconsistent.
    var a_mat = try GFMatrix.init(allocator, 3, 2); defer a_mat.deinit();
    try a_mat.set(0,0, gf.one); try a_mat.set(0,1, gf.zero);
    try a_mat.set(1,0, gf.zero); try a_mat.set(1,1, gf.one);
    try a_mat.set(2,0, gf.one); try a_mat.set(2,1, gf.one);

    var y_vec = try GFVector.init_slice_copy(allocator, &.{GFElement.new(1), GFElement.new(2), GFElement.new(4)});
    defer y_vec.deinit();

    var sol = try solve_linear_system(allocator, a_mat, y_vec);
    try testing.expect(sol == null);
}

test "solve_linear_system: dimension mismatch" {
    const allocator = testing.allocator;
    var a_mat = try GFMatrix.init(allocator, 2, 2); defer a_mat.deinit(); // 2x2
    var y_vec_wrong_len = try GFVector.initCapacity(allocator, 3); // len 3
    defer y_vec_wrong_len.deinit();
    try y_vec_wrong_len.append(gf.one); try y_vec_wrong_len.append(gf.one); try y_vec_wrong_len.append(gf.one);

    var sol = solve_linear_system(allocator, a_mat, y_vec_wrong_len);
    try testing.expectError(SolverError.MatrixDimensionMismatch, sol);
}

test "solve_linear_system: zero matrix A, zero vector y" {
    // Ax = y => 0x = 0. If o_vars > 0, multiple solutions (e.g. x=0, x=1, ...).
    // If o_vars = 0, unique empty solution.
    const allocator = testing.allocator;
    var a_mat = try GFMatrix.init(allocator, 2, 2); defer a_mat.deinit(); // Zero by default
    var y_vec = try GFVector.initCapacity(allocator, 2); defer y_vec.deinit(); // Zero by default
    try y_vec.append(gf.zero); try y_vec.append(gf.zero);

    var sol = try solve_linear_system(allocator, a_mat, y_vec);
    try testing.expect(sol == null); // Multiple solutions

    var a_mat_0_vars = try GFMatrix.init(allocator, 2, 0); defer a_mat_0_vars.deinit();
    var sol_0_vars = try solve_linear_system(allocator, a_mat_0_vars, y_vec);
    try assert_solution_equals(sol_0_vars, &.{}, allocator); // Should be an empty vector solution
}

test "solve_linear_system: zero matrix A, non-zero vector y" {
    // Ax = y => 0x = y. If y is non-zero, inconsistent.
    const allocator = testing.allocator;
    var a_mat = try GFMatrix.init(allocator, 2, 2); defer a_mat.deinit(); // Zero by default
    var y_vec = try GFVector.initCapacity(allocator, 2); defer y_vec.deinit();
    try y_vec.append(gf.zero); try y_vec.append(gf.one); // y = [0,1]

    var sol = try solve_linear_system(allocator, a_mat, y_vec);
    try testing.expect(sol == null); // Inconsistent
}

test "solve_linear_system: empty system (0 equations, 0 variables)" {
    const allocator = testing.allocator;
    var a_mat = try GFMatrix.init(allocator, 0,0); defer a_mat.deinit();
    var y_vec = try GFVector.init(allocator); defer y_vec.deinit();
    var sol = try solve_linear_system(allocator, a_mat, y_vec);
    try testing.expect(sol != null);
    if (sol) |s| {
        defer s.deinit();
        try testing.expect(s.items.len == 0);
    }
}

```
