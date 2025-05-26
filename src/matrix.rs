//! Implements matrix operations over GF(16).

use crate::types::{GFElement, GFMatrix, GFVector};
use crate::gf::{gf16_add, gf16_mul, gf16_sub}; // gf16_sub is same as gf16_add

// --- Implementation of GFMatrix helper functions ---
// The GFMatrix struct is defined in types.rs. Here we add methods to it.
impl GFMatrix {
    /// Creates a new matrix from a flat vector of data, rows, and columns.
    /// Panics if `data.len() != rows * cols`.
    pub fn new_with_data(rows: usize, cols: usize, data: Vec<GFElement>) -> Self {
        if data.len() != rows * cols {
            panic!("Data length does not match rows * cols");
        }
        GFMatrix { data, rows, cols }
    }

    /// Creates a new matrix filled with GFElement(0).
    /// Note: The `new` method in `types.rs` already does this.
    /// This provides an explicit `zero` constructor.
    pub fn zero(rows: usize, cols: usize) -> Self {
        GFMatrix {
            data: vec![GFElement(0); rows * cols],
            rows,
            cols,
        }
    }

    /// Creates an identity matrix of a given size.
    pub fn identity(size: usize) -> Self {
        let mut matrix = Self::zero(size, size);
        for i in 0..size {
            matrix.set(i, i, GFElement(1)); // GF(16) one
        }
        matrix
    }

    /// Gets an element at (r, c), returns None if out of bounds.
    /// This overrides/complements the one in types.rs if it existed with a different signature.
    /// The one in types.rs returned Option<&GFElement>. This returns Option<GFElement> (by value).
    pub fn get_opt(&self, r: usize, c: usize) -> Option<GFElement> {
        if r < self.rows && c < self.cols {
            Some(self.data[r * self.cols + c])
        } else {
            None
        }
    }
    
    /// Gets an element at (r, c), panics if out of bounds.
    /// Useful for internal operations where bounds are already checked.
    pub fn get_unsafe(&self, r: usize, c: usize) -> GFElement {
        // No explicit bounds check here, relies on caller or Vec's panic.
        // For safety and clarity, explicit check is better even if slightly redundant.
        if r >= self.rows || c >= self.cols {
            panic!("get_unsafe: Index out of bounds (r={}, c={}, rows={}, cols={})", r, c, self.rows, self.cols);
        }
        self.data[r * self.cols + c]
    }

    /// Sets an element at (r, c), panics if out of bounds.
    /// This is similar to the one in types.rs.
    pub fn set_val(&mut self, r: usize, c: usize, val: GFElement) {
        if r < self.rows && c < self.cols {
            self.data[r * self.cols + c] = val;
        } else {
            panic!("set_val: Index out of bounds (r={}, c={}, rows={}, cols={})", r, c, self.rows, self.cols);
        }
    }

    /// Returns the number of rows in the matrix.
    pub fn num_rows(&self) -> usize {
        self.rows
    }

    /// Returns the number of columns in the matrix.
    pub fn num_cols(&self) -> usize {
        self.cols
    }

    /// Converts matrix rows to a `Vec` of `GFVector`s.
    pub fn to_vectors(&self) -> Vec<GFVector> {
        let mut vecs = Vec::with_capacity(self.rows);
        for i in 0..self.rows {
            let row_start = i * self.cols;
            let row_end = row_start + self.cols;
            vecs.push(self.data[row_start..row_end].to_vec());
        }
        vecs
    }

    /// Creates a matrix from a `Vec` of `GFVector`s (rows).
    /// Panics if `vecs` is empty or if rows have inconsistent lengths.
    pub fn from_vectors(vecs: Vec<GFVector>) -> Self {
        if vecs.is_empty() {
            return Self::zero(0, 0); // Or panic, depending on desired behavior for empty input
        }
        let rows = vecs.len();
        let cols = vecs[0].len();
        let mut data = Vec::with_capacity(rows * cols);
        for vec in vecs {
            if vec.len() != cols {
                panic!("Inconsistent column lengths in input vectors");
            }
            data.extend_from_slice(&vec);
        }
        GFMatrix { data, rows, cols }
    }
}

// --- Standalone Matrix Operations ---

/// Adds two matrices over GF(16).
/// Returns Err if dimensions are incompatible.
pub fn matrix_add(a: &GFMatrix, b: &GFMatrix) -> Result<GFMatrix, &'static str> {
    if a.num_rows() != b.num_rows() || a.num_cols() != b.num_cols() {
        return Err("Matrices must have the same dimensions for addition");
    }
    let mut result_data = Vec::with_capacity(a.data.len());
    for i in 0..a.data.len() {
        result_data.push(gf16_add(a.data[i], b.data[i]));
    }
    Ok(GFMatrix::new_with_data(a.num_rows(), a.num_cols(), result_data))
}

/// Subtracts matrix b from matrix a over GF(16).
/// (Identical to addition in GF(2^n)).
/// Returns Err if dimensions are incompatible.
pub fn matrix_sub(a: &GFMatrix, b: &GFMatrix) -> Result<GFMatrix, &'static str> {
    matrix_add(a, b) // In GF(2^n), subtraction is XOR, same as addition
}

/// Multiplies each element of a matrix by a scalar in GF(16).
pub fn matrix_scalar_mul(scalar: GFElement, matrix: &GFMatrix) -> GFMatrix {
    let mut result_data = Vec::with_capacity(matrix.data.len());
    for val in &matrix.data {
        result_data.push(gf16_mul(scalar, *val));
    }
    GFMatrix::new_with_data(matrix.num_rows(), matrix.num_cols(), result_data)
}

/// Multiplies two matrices (a * b) over GF(16).
/// Returns Err if dimensions are incompatible (a.cols != b.rows).
pub fn matrix_mul(a: &GFMatrix, b: &GFMatrix) -> Result<GFMatrix, &'static str> {
    if a.num_cols() != b.num_rows() {
        return Err("Number of columns in the first matrix must equal number of rows in the second");
    }
    let result_rows = a.num_rows();
    let result_cols = b.num_cols();
    let mut result_matrix = GFMatrix::zero(result_rows, result_cols);

    for r in 0..result_rows {
        for c in 0..result_cols {
            let mut sum = GFElement(0);
            for k_idx in 0..a.num_cols() { // a.num_cols() or b.num_rows()
                let val_a = a.get_unsafe(r, k_idx);
                let val_b = b.get_unsafe(k_idx, c);
                sum = gf16_add(sum, gf16_mul(val_a, val_b));
            }
            result_matrix.set_val(r, c, sum);
        }
    }
    Ok(result_matrix)
}

/// Transposes a matrix over GF(16).
pub fn matrix_transpose(matrix: &GFMatrix) -> GFMatrix {
    let mut transposed_matrix = GFMatrix::zero(matrix.num_cols(), matrix.num_rows());
    for r in 0..matrix.num_rows() {
        for c in 0..matrix.num_cols() {
            transposed_matrix.set_val(c, r, matrix.get_unsafe(r, c));
        }
    }
    transposed_matrix
}

/// Multiplies a matrix by a vector (matrix * vector) over GF(16).
/// Treats the vector as a column vector.
/// Returns Err if dimensions are incompatible (matrix.cols != vector.len()).
pub fn matrix_vec_mul(matrix: &GFMatrix, vector: &GFVector) -> Result<GFVector, &'static str> {
    if matrix.num_cols() != vector.len() {
        return Err("Matrix columns must match vector length for multiplication");
    }
    let mut result_vector = Vec::with_capacity(matrix.num_rows());
    for r in 0..matrix.num_rows() {
        let mut sum = GFElement(0);
        for c in 0..matrix.num_cols() {
            sum = gf16_add(sum, gf16_mul(matrix.get_unsafe(r, c), vector[c]));
        }
        result_vector.push(sum);
    }
    Ok(result_vector)
}

/// Subtracts vector `b` from vector `a` over GF(16) (element-wise).
/// Returns Err if dimensions are incompatible.
pub fn matrix_sub_vectors_gfvector(a: &GFVector, b: &GFVector) -> Result<GFVector, &'static str> {
    if a.len() != b.len() {
        return Err("Vector dimensions must match for subtraction");
    }
    let mut result = Vec::with_capacity(a.len());
    for i in 0..a.len() {
        result.push(gf16_sub(a[i], b[i])); // gf16_sub is XOR, same as gf16_add
    }
    Ok(result)
}

/// Symmetrizes a square matrix M by computing M + M^T.
/// In characteristic 2, (M+M^T)[i,i] = M[i,i]+M[i,i] = 0.
/// Off-diagonal elements are M[i,j]+M[j,i].
/// If M is upper triangular, M_sym[i,i]=M[i,i], M_sym[i,j]=M[i,j] for i<j, M_sym[j,i]=M[i,j] for j<i.
/// This function computes M_sym = M + M^T directly.
pub fn matrix_symmetrize(matrix: &GFMatrix) -> Result<GFMatrix, &'static str> {
    if matrix.num_rows() != matrix.num_cols() {
        return Err("Matrix must be square to be symmetrized");
    }
    let n = matrix.num_rows();
    let mut sym_matrix = GFMatrix::zero(n, n);
    for r in 0..n {
        for c in 0..n {
            // M_sym[r,c] = M[r,c] + M[c,r]
            let val = gf16_add(matrix.get_unsafe(r,c), matrix.get_unsafe(c,r));
            sym_matrix.set_val(r,c, val);
        }
    }
    Ok(sym_matrix)
}


/// Multiplies a row vector (transpose of GFVector) by a matrix: v^T * M.
/// vector_lhs is treated as a 1xN row vector. matrix_rhs is NxK. Result is 1xK (GFVector).
pub fn matrix_vec_mul_transpose_gfvector(vector_lhs: &GFVector, matrix_rhs: &GFMatrix) -> Result<GFVector, &'static str> {
    if vector_lhs.len() != matrix_rhs.num_rows() {
        return Err("Vector length must match matrix rows for v^T * M multiplication");
    }
    let num_cols_result = matrix_rhs.num_cols();
    let mut result_vector = vec![GFElement(0); num_cols_result];

    for c_res in 0..num_cols_result { // For each column in the result vector (and matrix_rhs)
        let mut sum = GFElement(0);
        for r_m_idx in 0..matrix_rhs.num_rows() { // Summing down the column of matrix_rhs
            sum = gf16_add(sum, gf16_mul(vector_lhs[r_m_idx], matrix_rhs.get_unsafe(r_m_idx, c_res)));
        }
        result_vector[c_res] = sum;
    }
    Ok(result_vector)
}

/// Computes the dot product of two vectors: a^T * b.
pub fn vector_dot_product(a: &GFVector, b: &GFVector) -> Result<GFElement, &'static str> {
    if a.len() != b.len() {
        return Err("Vectors must have the same length for dot product");
    }
    if a.is_empty() { // Or b.is_empty(), since lengths must match
        return Ok(GFElement(0)); // Dot product of empty vectors is 0
    }
    let mut sum = GFElement(0);
    for i in 0..a.len() {
        sum = gf16_add(sum, gf16_mul(a[i], b[i]));
    }
    Ok(sum)
}


// --- Unit Tests ---
#[cfg(test)]
mod tests {
    use super::*;
    fn gf(val: u8) -> GFElement { GFElement(val) }
    // Helper to create GFVector from Vec<GFElement> for tests in this module
    fn vec_gf(data: Vec<GFElement>) -> GFVector { data }


    #[test]
    fn test_matrix_symmetrize() {
        // Test with an upper triangular matrix
        // U = [[1,2,3],
        //      [0,4,5],
        //      [0,0,6]]
        let u_data = vec![gf(1),gf(2),gf(3), gf(0),gf(4),gf(5), gf(0),gf(0),gf(6)];
        let u_matrix = GFMatrix::new_with_data(3,3, u_data);
        
        // S = U + U^T
        // S[0,0] = 1+1=0. S[1,1]=4+4=0. S[2,2]=6+6=0.
        // S[0,1] = U[0,1]+U[1,0] = 2+0=2. S[1,0]=S[0,1]=2.
        // S[0,2] = U[0,2]+U[2,0] = 3+0=3. S[2,0]=S[0,2]=3.
        // S[1,2] = U[1,2]+U[2,1] = 5+0=5. S[2,1]=S[1,2]=5.
        // Expected S = [[0,2,3],
        //               [2,0,5],
        //               [3,5,0]]
        let expected_s_data = vec![gf(0),gf(2),gf(3), gf(2),gf(0),gf(5), gf(3),gf(5),gf(0)];
        let s_matrix = matrix_symmetrize(&u_matrix).unwrap();
        assert_eq!(s_matrix.data, expected_s_data);

        // Test with a non-square matrix (should err)
        let non_square = GFMatrix::zero(2,3);
        assert!(matrix_symmetrize(&non_square).is_err());

        // Test with an already symmetric matrix
        // M = [[1,2],[2,3]] -> M+M^T = [[0,0],[0,0]]
        let m_sym_data = vec![gf(1),gf(2), gf(2),gf(3)];
        let m_sym = GFMatrix::new_with_data(2,2, m_sym_data);
        let expected_zero_data = vec![gf(0),gf(0), gf(0),gf(0)];
        assert_eq!(matrix_symmetrize(&m_sym).unwrap().data, expected_zero_data);
    }

    #[test]
    fn test_matrix_vec_mul_transpose_gfvector() {
        // v^T = [1, 2, 3] (1x3)
        // M   = [[1, 4],  (3x2)
        //        [2, 5],
        //        [3, 6]]
        // v^T * M = [ (1*1 + 2*2 + 3*3), (1*4 + 2*5 + 3*6) ]
        //         = [ (1^4^5), (4^A^2) ] (using 3*3=5, 2*5=A, 3*6=A^4=2)
        //         = [ (0), (4^A=E ^2 = C) ] = [0, C]
        let v = vec_gf(vec![gf(1), gf(2), gf(3)]);
        let m_data = vec![gf(1),gf(4), gf(2),gf(5), gf(3),gf(6)];
        let m = GFMatrix::new_with_data(3,2,m_data);
        let expected = vec_gf(vec![gf(0), gf(0x4)]);
        assert_eq!(matrix_vec_mul_transpose_gfvector(&v, &m).unwrap(), expected);

        let v_short = vec_gf(vec![gf(1), gf(2)]);
        assert!(matrix_vec_mul_transpose_gfvector(&v_short, &m).is_err());
    }

    #[test]
    fn test_vector_dot_product() {
        let v1 = vec_gf(vec![gf(1), gf(2), gf(3)]);
        let v2 = vec_gf(vec![gf(4), gf(5), gf(6)]);
        // 1*4 + 2*5 + 3*6 = 4 ^ A ^ (A^4=2) = 4^A=E ^2 = C
        assert_eq!(vector_dot_product(&v1, &v2).unwrap(), gf(0x4));
        
        let v_empty1 = vec_gf(vec![]);
        let v_empty2 = vec_gf(vec![]);
        assert_eq!(vector_dot_product(&v_empty1, &v_empty2).unwrap(), gf(0));

        let v_short = vec_gf(vec![gf(1)]);
        assert!(vector_dot_product(&v1, &v_short).is_err());
    }

    #[test]
    fn test_matrix_constructors_and_getters() {
        let m1_data = vec![gf(1), gf(2), gf(3), gf(4)];
        let m1 = GFMatrix::new_with_data(2, 2, m1_data.clone());
        assert_eq!(m1.num_rows(), 2);
        assert_eq!(m1.num_cols(), 2);
        assert_eq!(m1.get_opt(0,0), Some(gf(1)));
        assert_eq!(m1.get_unsafe(1,1), gf(4));
        assert_eq!(m1.get_opt(2,0), None);

        let m_zero = GFMatrix::zero(2, 3);
        assert_eq!(m_zero.get_unsafe(1,2), gf(0));
        assert_eq!(m_zero.num_rows(), 2);
        assert_eq!(m_zero.num_cols(), 3);

        let m_id = GFMatrix::identity(3);
        assert_eq!(m_id.get_unsafe(0,0), gf(1));
        assert_eq!(m_id.get_unsafe(0,1), gf(0));
        assert_eq!(m_id.get_unsafe(1,1), gf(1));
        assert_eq!(m_id.num_rows(), 3);
        assert_eq!(m_id.num_cols(), 3);
    }

    #[test]
    #[should_panic]
    fn test_new_with_data_panic() {
        GFMatrix::new_with_data(2,2, vec![gf(1)]);
    }
    
    #[test]
    fn test_matrix_set_val() {
        let mut m = GFMatrix::zero(2,2);
        m.set_val(0,1, gf(5));
        assert_eq!(m.get_unsafe(0,1), gf(5));
    }

    #[test]
    #[should_panic]
    fn test_set_val_panic() {
        let mut m = GFMatrix::zero(1,1);
        m.set_val(1,1, gf(1));
    }

    #[test]
    fn test_to_from_vectors() {
        let vecs = vec![vec![gf(1), gf(2)], vec![gf(3), gf(4)]];
        let m = GFMatrix::from_vectors(vecs.clone());
        assert_eq!(m.num_rows(), 2);
        assert_eq!(m.num_cols(), 2);
        assert_eq!(m.get_unsafe(0,1), gf(2));
        
        let recovered_vecs = m.to_vectors();
        assert_eq!(vecs, recovered_vecs);

        assert!(GFMatrix::from_vectors(vec![]).data.is_empty());
    }

    #[test]
    #[should_panic]
    fn test_from_vectors_panic() {
        GFMatrix::from_vectors(vec![vec![gf(1)], vec![gf(2), gf(3)]]);
    }

    #[test]
    fn test_matrix_addition_subtraction() {
        let m1 = GFMatrix::new_with_data(2,2, vec![gf(1), gf(2), gf(3), gf(4)]);
        let m2 = GFMatrix::new_with_data(2,2, vec![gf(5), gf(6), gf(7), gf(8)]);
        // 1^5=4, 2^6=4, 3^7=4, 4^8=12
        let expected_sum = GFMatrix::new_with_data(2,2, vec![gf(4), gf(4), gf(4), gf(12)]);
        assert_eq!(matrix_add(&m1, &m2).unwrap().data, expected_sum.data);
        assert_eq!(matrix_sub(&m1, &m2).unwrap().data, expected_sum.data); // add=sub

        let m3 = GFMatrix::zero(1,2);
        assert!(matrix_add(&m1, &m3).is_err());
    }

    #[test]
    fn test_matrix_scalar_multiplication() {
        let m = GFMatrix::new_with_data(2,2, vec![gf(1), gf(2), gf(3), gf(0x8)]); // 0x8 is x^3
        let scalar = gf(0x2); // x
        // x*1=x (2), x*x=x^2 (4), x*(x+1)=x^2+x (6), x*x^3=x^4=x+1 (3)
        let expected = GFMatrix::new_with_data(2,2, vec![gf(2), gf(4), gf(6), gf(3)]);
        assert_eq!(matrix_scalar_mul(scalar, &m).data, expected.data);
    }

    #[test]
    fn test_matrix_multiplication() {
        // A = [[1,2],[3,4]]   B = [[5,6],[7,1]]
        // A = [[01,10],[11,100]] B = [[101,110],[111,001]] (binary)
        let a = GFMatrix::new_with_data(2,2, vec![gf(1), gf(2), gf(3), gf(4)]);
        let b = GFMatrix::new_with_data(2,2, vec![gf(5), gf(6), gf(7), gf(1)]);

        // C[0,0] = (1*5) + (2*7) = (0x1*0x5) ^ (0x2*0x7) = 0x5 ^ (0x2*(x^2+x+1)=x^3+x^2+x = 0x8^0x4^0x2=0xE) = 0x5 ^ 0xE = 0xB
        // C[0,1] = (1*6) + (2*1) = (0x1*0x6) ^ (0x2*0x1) = 0x6 ^ 0x2 = 0x4
        // C[1,0] = (3*5) + (4*7) = (0x3*0x5) ^ (0x4*0x7)
        //   0x3*0x5 = (x+1)(x^2+1) = x^3+x+x^2+1 = 0x8^0x2^0x4^0x1 = 0xF
        //   0x4*0x7 = x^2(x^2+x+1) = x^4+x^3+x^2 = (x+1)+x^3+x^2 = 0x3^0x8^0x4 = 0xF
        //   0xF ^ 0xF = 0x0
        // C[1,1] = (3*6) + (4*1) = (0x3*0x6) ^ (0x4*0x1)
        //   0x3*0x6 = (x+1)(x^2+x) = x^3+x^2+x^2+x = x^3+x = 0x8^0x2=0xA
        //   0x4*0x1 = 0x4
        //   0xA ^ 0x4 = 0xE
        let expected = GFMatrix::new_with_data(2,2, vec![gf(0xB), gf(0x4), gf(0x0), gf(0xE)]);
        assert_eq!(matrix_mul(&a, &b).unwrap().data, expected.data);

        let m_id = GFMatrix::identity(2);
        assert_eq!(matrix_mul(&a, &m_id).unwrap().data, a.data);
        assert_eq!(matrix_mul(&m_id, &a).unwrap().data, a.data);
        
        let c = GFMatrix::zero(3,2); // Incompatible for a*c
        assert!(matrix_mul(&a, &c).is_err());
    }
    
    #[test]
    fn test_matrix_transpose() {
        let m = GFMatrix::new_with_data(2,3, vec![gf(1), gf(2), gf(3), gf(4), gf(5), gf(6)]);
        let mt = matrix_transpose(&m);
        assert_eq!(mt.num_rows(), 3);
        assert_eq!(mt.num_cols(), 2);
        assert_eq!(mt.get_unsafe(0,0), gf(1));
        assert_eq!(mt.get_unsafe(1,0), gf(2));
        assert_eq!(mt.get_unsafe(0,1), gf(4));
        assert_eq!(mt.get_unsafe(2,1), gf(6));
        
        // (A*B)^T = B^T * A^T
        let a = GFMatrix::new_with_data(1,2, vec![gf(1), gf(2)]);
        let b = GFMatrix::new_with_data(2,1, vec![gf(3), gf(4)]);
        let ab = matrix_mul(&a, &b).unwrap();
        let ab_t = matrix_transpose(&ab);
        
        let a_t = matrix_transpose(&a);
        let b_t = matrix_transpose(&b);
        let bt_at = matrix_mul(&b_t, &a_t).unwrap();
        assert_eq!(ab_t.data, bt_at.data);
    }

    #[test]
    fn test_matrix_vector_multiplication() {
        let matrix = GFMatrix::new_with_data(2,3, vec![
            gf(1), gf(2), gf(3),
            gf(4), gf(5), gf(6)
        ]);
        let vector = vec_gf(vec![gf(1), gf(2), gf(3)]); // Use helper
        // r0 = (1*1)^(2*2)^(3*3) = 1 ^ 4 ^ ( (x+1)(x+1) = x^2+1 = 0x4^0x1=0x5) = 1^4^5 = (0101^0101=0)
        // r1 = (4*1)^(5*2)^(6*3) = 4 ^ ( (x^2+1)x = x^3+x = 0xA) ^ ( (x^2+x)(x+1) = x^3+x = 0xA ) = 4^A^A = 4
        let expected_result = vec_gf(vec![gf(0), gf(4)]); // Use helper
        assert_eq!(matrix_vec_mul(&matrix, &vector).unwrap(), expected_result);

        let incompatible_vector = vec_gf(vec![gf(1), gf(2)]); // Use helper
        assert!(matrix_vec_mul(&matrix, &incompatible_vector).is_err());
    }

    #[test]
    fn test_matrix_sub_vectors_gfvector() {
        let v1 = vec_gf(vec![gf(5), gf(6), gf(7)]);
        let v2 = vec_gf(vec![gf(1), gf(2), gf(3)]);
        // 5^1=4, 6^2=4, 7^3=4
        let expected = vec_gf(vec![gf(4), gf(4), gf(4)]);
        assert_eq!(matrix_sub_vectors_gfvector(&v1, &v2).unwrap(), expected);

        let v3 = vec_gf(vec![gf(1)]);
        assert!(matrix_sub_vectors_gfvector(&v1, &v3).is_err());
    }
}
