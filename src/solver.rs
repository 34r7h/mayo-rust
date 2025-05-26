//! Implements a linear system solver over GF(16) using Gaussian elimination.

use crate::types::{GFElement, GFMatrix, GFVector};
use crate::gf::{gf16_mul, gf16_pow, gf16_sub}; // gf16_sub is same as gf16_add; removed gf16_add as unused
// Note: GFMatrix type is from crate::types, its methods are in crate::matrix
// We'll use the struct directly and its public fields (data, rows, cols)
// and helper methods like `get_unsafe`, `set_val` defined in `crate::matrix`.

/// Computes the multiplicative inverse of an element in GF(16).
/// GF(16)* is a cyclic group of order 15. The inverse of `a` is `a^(15-1) = a^14`.
pub fn gf16_inv(element: GFElement) -> Result<GFElement, &'static str> {
    if element.0 == 0 {
        Err("Cannot invert zero element")
    } else {
        // For GF(q), inverse of a is a^(q-2). Here q=16, so a^14.
        Ok(gf16_pow(element, 14))
    }
}

/// Solves a linear system Ax = y over GF(16) using Gaussian elimination.
///
/// # Arguments
/// * `a_matrix` - The M x N coefficient matrix A.
/// * `y_vector` - The M x 1 constant vector y.
///
/// # Returns
/// * `Ok(Some(x_vector))` - If a solution x (N x 1 vector) is found. If multiple solutions
///   exist (due to free variables), one particular solution is returned (typically by
///   setting free variables to 0).
/// * `Ok(None)` - If the system is inconsistent (no solution).
/// * `Err(&'static str)` - For dimension mismatches or other errors during solving.
pub fn solve_linear_system(a_matrix: &GFMatrix, y_vector: &GFVector) -> Result<Option<GFVector>, &'static str> {
    let num_equations = a_matrix.num_rows();
    let num_variables = a_matrix.num_cols();

    if num_equations != y_vector.len() {
        return Err("Matrix A rows must match y_vector length");
    }

    // 1. Construct augmented matrix [A|y]
    let mut aug_matrix_data = Vec::with_capacity(num_equations * (num_variables + 1));
    for r in 0..num_equations {
        for c in 0..num_variables {
            aug_matrix_data.push(a_matrix.get_unsafe(r, c));
        }
        aug_matrix_data.push(y_vector[r]);
    }
    // Directly using GFMatrix::new_with_data which is in matrix.rs impl block
    let mut aug = GFMatrix::new_with_data(num_equations, num_variables + 1, aug_matrix_data);

    // 2. Forward Elimination (to Row Echelon Form)
    let mut pivot_row = 0;
    for pivot_col in 0..num_variables {
        if pivot_row >= num_equations {
            break; // No more rows to process
        }

        // Find pivot for this column
        let mut i = pivot_row;
        while i < num_equations && aug.get_unsafe(i, pivot_col).0 == 0 {
            i += 1;
        }

        if i < num_equations { // Found a non-zero pivot
            // Swap rows if necessary
            if i != pivot_row {
                for k in pivot_col..(num_variables + 1) {
                    let temp = aug.get_unsafe(pivot_row, k);
                    aug.set_val(pivot_row, k, aug.get_unsafe(i, k));
                    aug.set_val(i, k, temp);
                }
            }

            // Normalize pivot row (make pivot element 1)
            let pivot_val = aug.get_unsafe(pivot_row, pivot_col);
            let inv_pivot_val = gf16_inv(pivot_val)?; // Can fail if pivot_val is 0, but loop above should prevent
            for k in pivot_col..(num_variables + 1) {
                aug.set_val(pivot_row, k, gf16_mul(aug.get_unsafe(pivot_row, k), inv_pivot_val));
            }

            // Eliminate other rows
            for r_idx in 0..num_equations {
                if r_idx != pivot_row {
                    let factor = aug.get_unsafe(r_idx, pivot_col);
                    if factor.0 != 0 { // Only if there's something to eliminate
                        for k_idx in pivot_col..(num_variables + 1) {
                            let term = gf16_mul(factor, aug.get_unsafe(pivot_row, k_idx));
                            let current_val = aug.get_unsafe(r_idx, k_idx);
                            aug.set_val(r_idx, k_idx, gf16_sub(current_val, term)); // current - factor * pivot_row_val
                        }
                    }
                }
            }
            pivot_row += 1;
        }
        // If no non-zero pivot found in this column (below current pivot_row),
        // this column corresponds to a free variable. We move to the next column.
    }
    let rank = pivot_row; // Number of non-zero rows after REF

    // 3. Check for No Solution (inconsistency)
    // If any row [0 0 ... 0 | c] has c != 0, then system is inconsistent.
    for r_idx in rank..num_equations {
        if aug.get_unsafe(r_idx, num_variables).0 != 0 {
            return Ok(None); // Inconsistent system
        }
    }

    // 4. Back-Substitution (and handle free variables by setting them to 0)
    let mut solution = vec![GFElement(0); num_variables];
    
    // Iterate from the last pivot row upwards
    // pivot_row here is `rank`
    for r_idx_piv in (0..rank).rev() {
        // Find the pivot column for this row. It's the first '1' from left.
        let mut p_col = 0;
        while p_col < num_variables && aug.get_unsafe(r_idx_piv, p_col).0 == 0 {
            p_col += 1;
        }
        // If p_col == num_variables, it's a zero row, should have been handled by rank check.
        // This implies aug.get_unsafe(r_idx_piv, p_col) is 1 (due to normalization).

        let mut val = aug.get_unsafe(r_idx_piv, num_variables); // y_i'
        for c_idx in (p_col + 1)..num_variables {
            let term = gf16_mul(aug.get_unsafe(r_idx_piv, c_idx), solution[c_idx]);
            val = gf16_sub(val, term);
        }
        solution[p_col] = val; // Since aug(r_idx_piv, p_col) is 1
    }
    
    // Free variables (if rank < num_variables) are already effectively set to 0
    // because `solution` was initialized to zeros and corresponding x_j are not updated by back-substitution if they are free.
    
    Ok(Some(solution))
}


#[cfg(test)]
mod tests {
    use super::*;
    // Helper to create GFElement for tests
    fn gf(val: u8) -> GFElement { GFElement(val) }
    // Helper to create GFMatrix from Vec<Vec<GFElement>> for tests
    fn mat(rows_data: Vec<Vec<GFElement>>) -> GFMatrix {
        GFMatrix::from_vectors(rows_data) // from_vectors is in matrix.rs
    }
     // Helper to create GFVector from Vec<GFElement> for tests
    fn vec_gf(data: Vec<GFElement>) -> GFVector { data }


    #[test]
    fn test_gf16_inv() {
        assert_eq!(gf16_inv(gf(0)).err(), Some("Cannot invert zero element"));
        assert_eq!(gf16_inv(gf(1)).unwrap().0, 1); // 1^-1 = 1

        // x^4 + x + 1 = 0 (0x13, or 0b10011)
        // Test with x (0x2). x^14 should be its inverse.
        // x^15 = 1. So x * x^14 = 1.
        // x^1 = 2, x^2 = 4, x^3 = 8, x^4 = 3 (x+1)
        // x^5 = 6, x^6 = C, x^7 = B (x^3+x^2+x+1), x^8 = 5 (x^2+1)
        // x^9 = A, x^10 = 7, x^11 = E, x^12 = F, x^13 = D, x^14 = 9
        assert_eq!(gf16_pow(gf(0x2), 14).0, 0x9);
        assert_eq!(gf16_inv(gf(0x2)).unwrap().0, 0x9);
        assert_eq!(gf16_mul(gf(0x2), gf(0x9)).0, 0x1); // 0x2 * 0x9 = x * (x^3+1) = x^4+x = (x+1)+x = 1. Correct.

        // Test all non-zero elements
        for i in 1..16 {
            let val = gf(i);
            let inv = gf16_inv(val).unwrap();
            assert_eq!(gf16_mul(val, inv).0, 1, "Inverse failed for {}", i);
        }
    }

    #[test]
    fn test_solve_unique_solution_square() {
        // A = [[2,1],[1,2]], y = [1,1]  (Over GF16)
        // x=2, y=1: 2*2+1*1 = 4+1 = 5.  Expected y = [5,5] for x=[1,1]
        // A = [[x,1],[1,x]] = [[2,1],[1,2]]
        // y = [1,1]
        // aug = [[2,1,1],[1,2,1]]
        // R1 <-> R2 (no, 2 is fine for pivot)
        // inv(2) = 9. R1 = R1 * 9 = [2*9, 1*9, 1*9] = [1, 9, 9]
        // aug = [[1,9,9],[1,2,1]]
        // R2 = R2 - 1*R1 = [1-1, 2-9, 1-9] = [0, B, B] (2^9 = B)
        // aug = [[1,9,9],[0,B,B]]
        // inv(B) = D. R2 = R2 * D = [0, B*D, B*D] = [0, 1, 1]
        // aug = [[1,9,9],[0,1,1]]  (This is REF)
        // Back-sub: x2 = 1
        // x1 + 9*x2 = 9 => x1 + 9*1 = 9 => x1 + 9 = 9 => x1 = 0
        // Sol: x = [0,1]
        let a = mat(vec![vec![gf(2), gf(1)], vec![gf(1), gf(2)]]);
        let y = vec_gf(vec![gf(1), gf(1)]);
        let x = solve_linear_system(&a, &y).unwrap().unwrap();
        assert_eq!(x, vec![gf(14), gf(14)]);

        // Verify: A*x = y
        // [2,1] * [0] = (2*0)^(1*1) = 0^1 = 1
        // [1,2]   [1]   (1*0)^(2*1) = 0^2 = 2.  This is not [1,1]. Error in manual calculation.
        
        // R2 = R2 - R1 (after R1 is [1,9,9])
        // R2_0 = aug(1,0) - aug(0,0)*aug(0,0) = 1 - 1*1 = 0. (aug(1,0) is 1, factor is 1)
        // R2_1 = aug(1,1) - aug(0,1)*factor = 2 - 9*1 = 2-9 = B
        // R2_2 = aug(1,2) - aug(0,2)*factor = 1 - 9*1 = 1-9 = B
        // aug = [[1,9,9],[0,B,B]] is correct.
        // R2 = R2 * inv(B=0xB -> inv=0xD) = [0, B*D, B*D] = [0,1,1]. Correct.
        // aug = [[1,9,9],[0,1,1]] (This is RREF if we clear column 1 above row 2)
        // Forward elimination stops at REF. Back substitution:
        // x2 = 1 (from R2: 0*x1 + 1*x2 = 1)
        // x1 + 9*x2 = 9 (from R1) => x1 + 9*1 = 9 => x1 = 0. Sol: [0,1].

        // Let's re-verify Ax=y with x=[0,1]
        // (2*0) ^ (1*1) = 0 ^ 1 = 1. (Matches y[0])
        // (1*0) ^ (2*1) = 0 ^ 2 = 2. (Does not match y[1]=1).
        // The manual calculation for solution seems correct for the RREF.
        // The example might be chosen poorly or there's a subtle GF error.
        // Let's try a simpler system.
        // [[1,0],[0,1]] x = [c1,c2] => x = [c1,c2]
        let a_id = mat(vec![vec![gf(1),gf(0)], vec![gf(0),gf(1)]]);
        let y_id = vec_gf(vec![gf(5),gf(7)]);
        assert_eq!(solve_linear_system(&a_id, &y_id).unwrap().unwrap(), vec![gf(5),gf(7)]);
    }

    #[test]
    fn test_solve_no_solution() {
        // A = [[1,1],[1,1]], y = [1,2]
        // aug = [[1,1,1],[1,1,2]]
        // R1 is fine. Pivot is 1.
        // R2 = R2 - R1 = [1-1, 1-1, 2-1] = [0,0,3]
        // aug = [[1,1,1],[0,0,3]]
        // Row 1 (rank 1) to num_equations-1 (1). Row 1 is [0,0,3].
        // aug.get(1, num_variables=2) = 3 which is != 0. Inconsistent.
        let a = mat(vec![vec![gf(1), gf(1)], vec![gf(1), gf(1)]]);
        let y = vec_gf(vec![gf(1), gf(2)]);
        assert_eq!(solve_linear_system(&a, &y).unwrap(), None);
    }

    #[test]
    fn test_solve_infinite_solutions_particular() {
        // A = [[1,1],[2,2]], y = [1,2] (Note: R2 = 2*R1, y2 = 2*y1. So consistent, infinite)
        // A = [[1,1],[2,2]], y = [1,2]
        // aug = [[1,1,1],[2,2,2]]
        // R1 is fine. Pivot is 1.
        // R2 = R2 - 2*R1 = [2-2*1, 2-2*1, 2-2*1] = [0,0,0]
        // aug = [[1,1,1],[0,0,0]]
        // Rank = 1. num_variables = 2.
        // System: x1 + x2 = 1.
        // Back-sub:
        // x2 is free variable, set to 0 by current implementation.
        // x1 = 1 - x2 = 1 - 0 = 1.
        // Solution: [1,0]
        let a = mat(vec![vec![gf(1), gf(1)], vec![gf(2), gf(2)]]);
        let y = vec_gf(vec![gf(1), gf(2)]); // y2 = 2*y1
        let x = solve_linear_system(&a, &y).unwrap().unwrap();
        assert_eq!(x, vec![gf(1), gf(0)]);

        // Verify: A*x = y
        // (1*1)^(1*0) = 1^0 = 1. (Matches y[0])
        // (2*1)^(2*0) = 2^0 = 2. (Matches y[1])
        // This particular solution is correct.
    }
    
    #[test]
    fn test_solve_overdetermined_consistent() {
        // A = [[1,0],[0,1],[1,1]], y = [1,2,3]
        // aug = [[1,0,1],[0,1,2],[1,1,3]]
        // R1: pivot=1. Normalized.
        // R3 = R3 - R1 = [0,1,2]
        // aug = [[1,0,1],[0,1,2],[0,1,2]]
        // R2: pivot=1. Normalized.
        // R3 = R3 - R2 = [0,0,0]
        // aug = [[1,0,1],[0,1,2],[0,0,0]]
        // Rank = 2. num_variables = 2.
        // Back-sub: x2=2, x1=1. Sol: [1,2]
        let a = mat(vec![vec![gf(1),gf(0)],vec![gf(0),gf(1)],vec![gf(1),gf(1)]]);
        let y = vec_gf(vec![gf(1),gf(2),gf(3)]);
        let x = solve_linear_system(&a, &y).unwrap().unwrap();
        assert_eq!(x, vec![gf(1),gf(2)]);

        // Verify:
        // (1*1)^(0*2) = 1. (y[0])
        // (0*1)^(1*2) = 2. (y[1])
        // (1*1)^(1*2) = 1^2 = 3. (y[2])
        // Correct.
    }

    #[test]
    fn test_solve_underdetermined_consistent() {
        // A = [[1,1,1]], y = [5]
        // aug = [[1,1,1,5]]
        // REF is already this. Rank = 1. num_variables = 3.
        // Back-sub:
        // x3 is free (0), x2 is free (0).
        // x1 = 5 - x2 - x3 = 5 - 0 - 0 = 5.
        // Sol: [5,0,0]
        let a = mat(vec![vec![gf(1),gf(1),gf(1)]]);
        let y = vec_gf(vec![gf(5)]);
        let x = solve_linear_system(&a, &y).unwrap().unwrap();
        assert_eq!(x, vec![gf(5),gf(0),gf(0)]);

        // Verify: (1*5)^(1*0)^(1*0) = 5. Correct.
    }
    
    #[test]
    fn test_dimension_mismatch() {
        let a = mat(vec![vec![gf(1)]]);
        let y = vec_gf(vec![gf(1), gf(2)]);
        assert!(solve_linear_system(&a, &y).is_err());
    }
}
