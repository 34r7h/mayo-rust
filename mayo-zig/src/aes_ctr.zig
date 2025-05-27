const std = @import("std");
const testing = std.testing;
const mem = std.mem;
const crypto = std.crypto;
const params = @import("params.zig"); // Assuming this file will exist with necessary constants

// Error types
pub const AesCtrError = error{
    InvalidKeyLength,
    OutputBufferTooSmall,
    EncryptionError,
    AllocationFailed,
};

// AES-128-CTR PRNG context to maintain state for sequential calls (for P1 then P2)
const Aes128CtrPrngContext = struct {
    cipher: crypto.Cipher.Aes128Ecb,
    iv: [16]u8, // Current IV/counter block
    buffer: [16]u8, // Buffer for keystream block
    buffer_pos: usize, // Current position in the buffer

    const block_size = 16;

    pub fn init(key: [16]u8, initial_iv_seed: [12]u8) Aes128CtrPrngContext {
        var iv_full: [16]u8 = .{0} ** 16;
        mem.copy(u8, iv_full[0..12], initial_iv_seed[0..12]); 
        // The last 4 bytes are the counter, starting at 0.
        // std.mem.writeIntBig(u32, iv_full[12..16], 0); // Counter initialized to 0 by .{0}**16

        return Aes128CtrPrngContext{
            .cipher = crypto.Cipher.Aes128Ecb.init(key),
            .iv = iv_full,
            .buffer = .{0} ** block_size,
            .buffer_pos = block_size, // Buffer is initially empty, force generation
        };
    }

    fn increment_counter(self: *Aes128CtrPrngContext) void {
        // Increment the 32-bit big-endian counter part of the IV
        var counter_val = std.mem.readIntBig(u32, self.iv[12..16]);
        counter_val +%= 1;
        std.mem.writeIntBig(u32, self.iv[12..16], counter_val);
        // TODO: Handle counter overflow if this PRNG is used for extremely long outputs,
        // though for MAYO key derivation, it's unlikely.
    }

    // Generates keystream bytes.
    pub fn-beta squeezebytes(self: *Aes128CtrPrngContext, output: []u8) void {
        var out_offset: usize = 0;
        while (out_offset < output.len) {
            if (self.buffer_pos == block_size) {
                // Buffer is empty, generate a new block of keystream
                self.cipher.encrypt(self.iv, self.buffer[0..block_size]);
                self.increment_counter();
                self.buffer_pos = 0;
            }

            const remaining_in_buffer = block_size - self.buffer_pos;
            const remaining_to_output = output.len - out_offset;
            const bytes_to_copy = @min(remaining_in_buffer, remaining_to_output);

            mem.copy(u8, output[out_offset .. out_offset + bytes_to_copy], 
                       self.buffer[self.buffer_pos .. self.buffer_pos + bytes_to_copy]);
            
            self.buffer_pos += bytes_to_copy;
            out_offset += bytes_to_copy;
        }
    }
};


/// aes128_ctr_prng generates `output.len` pseudorandom bytes using AES-128-CTR.
/// The key is `key`.
/// The IV is constructed from `iv_seed` (12 bytes) and a 4-byte counter starting from `initial_block_offset`.
/// This function is suitable for a single call. For stateful PRNG (like for P1 then P2),
/// use Aes128CtrPrngContext directly.
pub fn aes128_ctr_prng_oneshot(
    key: [16]u8,
    iv_seed: [12]u8, // First 12 bytes of IV, last 4 are counter
    initial_block_offset: u32, // Starting value for the 32-bit counter
    output: []u8,
) void {
    var cipher = crypto.Cipher.Aes128Ecb.init(key);
    var current_iv: [16]u8 = .{0} ** 16;
    mem.copy(u8, current_iv[0..12], iv_seed[0..12]);
    std.mem.writeIntBig(u32, current_iv[12..16], initial_block_offset);

    var keystream_block: [16]u8 = undefined;
    var out_offset: usize = 0;
    const block_size = 16;

    while (out_offset < output.len) {
        cipher.encrypt(current_iv, keystream_block[0..block_size]);

        const remaining_len = output.len - out_offset;
        const bytes_to_copy = @min(remaining_len, block_size);
        
        mem.copy(u8, output[out_offset .. out_offset + bytes_to_copy], keystream_block[0..bytes_to_copy]);
        out_offset += bytes_to_copy;

        if (out_offset < output.len) { // Avoid incrementing if we just filled the buffer
            var counter_val = std.mem.readIntBig(u32, current_iv[12..16]);
            counter_val +%= 1;
            std.mem.writeIntBig(u32, current_iv[12..16], counter_val);
            // TODO: Handle counter overflow (highly unlikely for this use case)
        }
    }
}

// For MAYO, P1 and P2 are derived from pk_seed.
// The C reference uses aes128ctr_init with pk_seed and a zero nonce (which implies IV),
// then calls aes128ctr_squeezebytes. This means a stateful context.
// The `randombytes_ctrdrbg.c` in MAYO-C uses a fixed IV for its AES_128_CTR call.
// Let's assume a fixed IV (e.g., all zeros for the 12-byte part) for deriving P1/P2.

const default_iv_seed_for_derivation: [12]u8 = .{0} ** 12;

/// Derives P1 bytes.
/// `P1_BYTES` is the length of P1 from `params.zig`.
pub fn derive_p1_bytes(
    allocator: mem.Allocator,
    pk_seed: [params.PK_SEED_BYTES]u8,
) !([params.P1_BYTES]u8) {
    // Ensure pk_seed is 16 bytes for AES-128 key
    if (params.PK_SEED_BYTES != 16) {
        @compileError("PK_SEED_BYTES must be 16 for AES-128 key in derive_p1_bytes");
    }

    var p1_bytes_array: [params.P1_BYTES]u8 = undefined;
    
    // Use the one-shot PRNG for P1
    aes128_ctr_prng_oneshot(pk_seed, default_iv_seed_for_derivation, 0, &p1_bytes_array);
    
    // If allocation was strictly necessary, this would be different:
    // var p1_bytes_slice = try allocator.alloc(u8, params.P1_BYTES);
    // errdefer allocator.free(p1_bytes_slice);
    // aes128_ctr_prng_oneshot(pk_seed, default_iv_seed_for_derivation, 0, p1_bytes_slice);
    // mem.copy(u8, &p1_bytes_array, p1_bytes_slice); // If returning fixed array

    _ = allocator; // Not used if returning fixed array directly
    return p1_bytes_array;
}

/// Derives P2 bytes.
/// `P2_BYTES` is the length of P2 from `params.zig`.
/// This function demonstrates how to use the stateful context if P1 and P2 were generated sequentially
/// from the *same* PRNG stream.
/// However, the prompt implies P1 and P2 can be derived independently if `aes128_ctr_prng`
/// takes an offset. The C reference `MAYO_generate_PK_ECC` re-initializes for P1 and P2,
/// but uses the same key (pk_seed) and nonce (which is zero).
/// If `aes128ctr_init` is called with the same key and nonce, it produces the same stream.
/// `aes128ctr_squeezebytes` then pulls bytes.
/// The critical aspect is that the *counter* must be different.
/// If P1 used blocks 0 to N-1, P2 must start from block N.

pub fn derive_p2_bytes_stateful(
    prng_ctx: *Aes128CtrPrngContext, // Assumes P1 was already generated using this context
    allocator: mem.Allocator,
) !([params.P2_BYTES]u8) {
    var p2_bytes_array: [params.P2_BYTES]u8 = undefined;
    prng_ctx.squeezebytes(&p2_bytes_array);

    _ = allocator;
    return p2_bytes_array;
}

// Alternative derive_p2_bytes if it's independent but needs to start after P1's blocks
pub fn derive_p2_bytes_offset(
    allocator: mem.Allocator,
    pk_seed: [params.PK_SEED_BYTES]u8,
) !([params.P2_BYTES]u8) {
    if (params.PK_SEED_BYTES != 16) {
        @compileError("PK_SEED_BYTES must be 16 for AES-128 key in derive_p2_bytes_offset");
    }

    var p2_bytes_array: [params.P2_BYTES]u8 = undefined;

    // Calculate the number of blocks P1 would have consumed
    const p1_num_blocks: u32 = @divFloor(params.P1_BYTES + 15, 16);
    
    aes128_ctr_prng_oneshot(pk_seed, default_iv_seed_for_derivation, p1_num_blocks, &p2_bytes_array);
    
    _ = allocator;
    return p2_bytes_array;
}


test "AES-128-CTR PRNG oneshot basic" {
    var key: [16]u8 = .{0xAA} ** 16;
    var iv_seed: [12]u8 = .{0xBB} ** 12;
    var output: [32]u8 = undefined;

    aes128_ctr_prng_oneshot(key, iv_seed, 0, &output);
    // We don't have standard test vectors here, so just check it runs.
    // And check that output is not all zeros (highly unlikely for AES output).
    var all_zeros = true;
    for (output) |b| {
        if (b != 0) {
            all_zeros = false;
            break;
        }
    }
    try testing.expect(!all_zeros);

    // Test with an offset
    var output2: [16]u8 = undefined;
    aes128_ctr_prng_oneshot(key, iv_seed, 2, &output2); // Start from block 2
    
    all_zeros = true;
    for (output2) |b| {
        if (b != 0) {
            all_zeros = false;
            break;
        }
    }
    try testing.expect(!all_zeros);

    // Expect output[0..16] and output2 to be different if offset works
    // (output2 should be output[32..48] from a longer stream)
    // This is true if output was 48 bytes long: output[0..16], output[16..32], output[32..48]
    // output2 is block 2. output[16..32] is block 1. So they should be different.
    try testing.expect(!mem.eql(u8, output[16..32], output2[0..16]));
}

test "AES-128-CTR PRNG context basic" {
    var key: [16]u8 = .{0xCC} ** 16;
    var iv_seed: [12]u8 = .{0xDD} ** 12;
    
    var ctx = Aes128CtrPrngContext.init(key, iv_seed);

    var output1: [20]u8 = undefined;
    ctx.squeezebytes(&output1);

    var output2: [20]u8 = undefined;
    ctx.squeezebytes(&output2);

    // Check that output1 and output2 are different
    try testing.expect(!mem.eql(u8, &output1, &output2));

    // Check for non-zero output
    var all_zeros = true;
    for (output1) |b| { if (b != 0) { all_zeros = false; break; } }
    try testing.expect(!all_zeros);
    all_zeros = true;
    for (output2) |b| { if (b != 0) { all_zeros = false; break; } }
    try testing.expect(!all_zeros);

    // Test continuity: generate 32 bytes with oneshot vs context
    var os_out: [32]u8 = undefined;
    aes128_ctr_prng_oneshot(key, iv_seed, 0, &os_out);

    var ctx_reinit = Aes128CtrPrngContext.init(key, iv_seed);
    var ctx_out_1: [16]u8 = undefined;
    var ctx_out_2: [16]u8 = undefined;
    ctx_reinit.squeezebytes(&ctx_out_1);
    ctx_reinit.squeezebytes(&ctx_out_2);
    
    try testing.expect(mem.eql(u8, os_out[0..16], &ctx_out_1));
    try testing.expect(mem.eql(u8, os_out[16..32], &ctx_out_2));
}

// Test stubs for derive functions - require params.zig
// test "derive_p1_bytes basic" {
//     // Requires params.P1_BYTES and params.PK_SEED_BYTES to be defined
//     if (@hasDecl(params, "P1_BYTES") and @hasDecl(params, "PK_SEED_BYTES")) {
//         if (params.PK_SEED_BYTES == 16) {
//             var seed_pk: [params.PK_SEED_BYTES]u8 = .{0xEE} ** params.PK_SEED_BYTES;
//             const p1 = try derive_p1_bytes(std.testing.allocator, seed_pk);
//             try testing.expect(p1.len == params.P1_BYTES);
//         } else {
//            // Skip test or error, PK_SEED_BYTES must be 16
//         }
//     }
// }

// test "derive_p2_bytes_offset basic" {
//     // Requires params.P1_BYTES, params.P2_BYTES, params.PK_SEED_BYTES
//     if (@hasDecl(params, "P1_BYTES") and @hasDecl(params, "P2_BYTES") and @hasDecl(params, "PK_SEED_BYTES")) {
//         if (params.PK_SEED_BYTES == 16) {
//             var seed_pk: [params.PK_SEED_BYTES]u8 = .{0xFF} ** params.PK_SEED_BYTES;
//             const p2 = try derive_p2_bytes_offset(std.testing.allocator, seed_pk);
//             try testing.expect(p2.len == params.P2_BYTES);
//         }
//     }
// }

// test "derive_p1_p2_stateful" {
//     if (@hasDecl(params, "P1_BYTES") and @hasDecl(params, "P2_BYTES") and @hasDecl(params, "PK_SEED_BYTES")) {
//         if (params.PK_SEED_BYTES == 16) {
//             var seed_pk: [params.PK_SEED_BYTES]u8 = .{0x1A} ** params.PK_SEED_BYTES;
//             var iv_seed: [12]u8 = .{0} ** 12;
            
//             var prng_ctx = Aes128CtrPrngContext.init(seed_pk, iv_seed);
            
//             var p1_val: [params.P1_BYTES]u8 = undefined;
//             prng_ctx.squeezebytes(&p1_val);

//             const p2_val = try derive_p2_bytes_stateful(&prng_ctx, std.testing.allocator);
//             try testing.expect(p2_val.len == params.P2_BYTES);

//             // Compare with offset method
//             var p1_oneshot: [params.P1_BYTES]u8 = undefined;
//             aes128_ctr_prng_oneshot(seed_pk, iv_seed, 0, &p1_oneshot);
//             try testing.expect(mem.eql(u8, &p1_val, &p1_oneshot));

//             const p1_blocks = @divFloor(params.P1_BYTES + 15, 16);
//             var p2_offset_val: [params.P2_BYTES]u8 = undefined;
//             aes128_ctr_prng_oneshot(seed_pk, iv_seed, p1_blocks, &p2_offset_val);
//             try testing.expect(mem.eql(u8, &p2_val, &p2_offset_val));

//         }
//     }
// }

// Note: The `derive_pX_bytes` functions are defined to return fixed-size arrays `[SIZE]u8`.
// This requires `params.P1_BYTES` and `params.P2_BYTES` to be compile-time constants.
// The use of `std.mem.Allocator` is therefore only for potential internal temporary allocations
// if the functions were more complex, or if they returned `[]u8` slices (which they don't per signature).
// The current implementations fill stack-allocated arrays directly.
// The allocator parameter is kept to match the requested signature but isn't used in the simplified path.
// If params.P1_BYTES or P2_BYTES are very large, returning them by value might be an issue,
// but typical crypto parameter sizes are manageable.
```
