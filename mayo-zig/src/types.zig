// mayo-zig/src/types.zig
const std = @import("std");
const Allocator = std.mem.Allocator;

// Field element for GF(16), represented as a nibble.
// The actual value should be in the lower 4 bits of a u8.
pub const GFElement = struct {
    val: u4,

    pub fn new(value: u8) GFElement {
        // Ensure value is a valid nibble.
        // For simplicity in this example, direct cast. Add validation if needed.
        return GFElement{ .val = @truncate(u4, value) };
    }

    pub fn value(self: GFElement) u8 {
        return self.val;
    }
};

// Vector of field elements.
pub const GFVector = std.ArrayList(GFElement);

// Matrix of field elements (row-major storage).
pub const GFMatrix = struct {
    data: GFVector,
    rows: usize,
    cols: usize,
    allocator: Allocator,

    pub fn new(allocator: Allocator, rows: usize, cols: usize) !GFMatrix {
        var data_list = GFVector.init(allocator);
        errdefer data_list.deinit();
        try data_list.resize(rows * cols); // Initializes with default GFElement (0)
        // To initialize with a specific default, e.g. GFElement.new(0):
        // for (0..(rows*cols)) |_| {
        //     try data_list.append(GFElement.new(0));
        // }
        return GFMatrix{
            .data = data_list,
            .rows = rows,
            .cols = cols,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *GFMatrix) void {
        self.data.deinit();
    }
    
    // Helper to get element (row, col)
    pub fn get(self: GFMatrix, r: usize, c: usize) ?GFElement {
        if (r < self.rows and c < self.cols) {
            return self.data.items[r * self.cols + c];
        } else {
            return null;
        }
    }

    // Helper to set element (row, col)
    pub fn set(self: *GFMatrix, r: usize, c: usize, val: GFElement) void {
        if (r < self.rows and c < self.cols) {
            self.data.items[r * self.cols + c] = val;
        }
    }

    // Helper to get underlying slice of GFElements
    pub fn slice(self: GFMatrix) []GFElement {
        return self.data.items;
    }
    
    // num_rows and num_cols to match Rust API for matrix.rs porting
    pub fn num_rows(self: GFMatrix) usize {
        return self.rows;
    }

    pub fn num_cols(self: GFMatrix) usize {
        return self.cols;
    }

    // from_vectors (useful for tests and other constructions)
    // Assumes all inner vectors have the same length.
    pub fn from_vectors(allocator: Allocator, vector_of_vectors: []const GFVector) !GFMatrix {
        if (vector_of_vectors.len == 0) {
            return GFMatrix.new(allocator, 0, 0);
        }
        const rows = vector_of_vectors.len;
        const cols = if (rows > 0) vector_of_vectors[0].items.len else 0;
        
        var matrix = try GFMatrix.new(allocator, rows, cols);
        errdefer matrix.deinit();

        for (vector_of_vectors, 0..) |row_vec, r| {
            if (row_vec.items.len != cols) {
                return error.InconsistentRowLengths;
            }
            for (row_vec.items, 0..) |val, c| {
                matrix.set(r, c, val);
            }
        }
        return matrix;
    }
};

// Cryptographic types - using ArrayList(u8) for dynamically sized byte vectors.
// For fixed-size arrays, you would use [N]u8.
// The choice depends on whether sizes are known at compile time or vary.
// The Rust code uses Vec<u8>, so ArrayList(u8) is a closer equivalent.

pub const SeedSK = struct {
    bytes: std.ArrayList(u8),

    pub fn new(allocator: Allocator, initial_bytes: []const u8) !SeedSK {
        var list = std.ArrayList(u8).init(allocator);
        try list.appendSlice(initial_bytes);
        return .{ .bytes = list };
    }
    pub fn deinit(self: *SeedSK) void { self.bytes.deinit(); }
    pub fn slice(self: SeedSK) []u8 { return self.bytes.items; }
};

pub const SeedPK = struct {
    bytes: std.ArrayList(u8),
    pub fn new(allocator: Allocator, initial_bytes: []const u8) !SeedPK {
        var list = std.ArrayList(u8).init(allocator);
        try list.appendSlice(initial_bytes);
        return .{ .bytes = list };
    }
    pub fn deinit(self: *SeedPK) void { self.bytes.deinit(); }
    pub fn slice(self: SeedPK) []u8 { return self.bytes.items; }
};

pub const CompactSecretKey = struct { // Represents SeedSK
    bytes: std.ArrayList(u8),
    allocator: Allocator,

    // For WASM, functions to create from JS provided bytes might be needed.
    // For now, a simple constructor from a slice.
    pub fn new(allocator: Allocator, initial_bytes: []const u8) !CompactSecretKey {
        var list = std.ArrayList(u8).init(allocator);
        errdefer if(list.items.len ==0 and initial_bytes.len > 0) list.deinit(); // clean up if appendSlice fails
        try list.appendSlice(initial_bytes);
        return .{ .bytes = list, .allocator = allocator };
    }
    
    pub fn deinit(self: *CompactSecretKey) void {
        self.bytes.deinit();
    }

    pub fn get_bytes(self: CompactSecretKey) []const u8 {
        return self.bytes.items;
    }
    
    // clone method if needed
    pub fn clone(self: CompactSecretKey) !CompactSecretKey {
        return CompactSecretKey.new(self.allocator, self.bytes.items);
    }
};

pub const CompactPublicKey = struct { // Represents SeedPK || P3_bytes or similar
    bytes: std.ArrayList(u8),
    allocator: Allocator,

    pub fn new(allocator: Allocator, initial_bytes: []const u8) !CompactPublicKey {
        var list = std.ArrayList(u8).init(allocator);
        errdefer if(list.items.len ==0 and initial_bytes.len > 0) list.deinit();
        try list.appendSlice(initial_bytes);
        return .{ .bytes = list, .allocator = allocator };
    }
    pub fn deinit(self: *CompactPublicKey) void { self.bytes.deinit(); }
    pub fn get_bytes(self: CompactPublicKey) []const u8 { return self.bytes.items; }
    pub fn clone(self: CompactPublicKey) !CompactPublicKey {
        return CompactPublicKey.new(self.allocator, self.bytes.items);
    }
};

pub const ExpandedSecretKey = struct {
    bytes: std.ArrayList(u8),
    allocator: Allocator,
    pub fn new(allocator: Allocator, initial_bytes: []const u8) !ExpandedSecretKey {
        var list = std.ArrayList(u8).init(allocator);
        errdefer if(list.items.len ==0 and initial_bytes.len > 0) list.deinit();
        try list.appendSlice(initial_bytes);
        return .{ .bytes = list, .allocator = allocator };
    }
    pub fn deinit(self: *ExpandedSecretKey) void { self.bytes.deinit(); }
    pub fn get_bytes(self: ExpandedSecretKey) []const u8 { return self.bytes.items; }
    pub fn clone(self: ExpandedSecretKey) !ExpandedSecretKey {
        return ExpandedSecretKey.new(self.allocator, self.bytes.items);
    }
};

pub const ExpandedPublicKey = struct {
    bytes: std.ArrayList(u8),
    allocator: Allocator,
    pub fn new(allocator: Allocator, initial_bytes: []const u8) !ExpandedPublicKey {
        var list = std.ArrayList(u8).init(allocator);
        errdefer if(list.items.len ==0 and initial_bytes.len > 0) list.deinit();
        try list.appendSlice(initial_bytes);
        return .{ .bytes = list, .allocator = allocator };
    }
    pub fn deinit(self: *ExpandedPublicKey) void { self.bytes.deinit(); }
    pub fn get_bytes(self: ExpandedPublicKey) []const u8 { return self.bytes.items; }
    pub fn clone(self: ExpandedPublicKey) !ExpandedPublicKey {
        return ExpandedPublicKey.new(self.allocator, self.bytes.items);
    }
};

pub const Signature = struct { // Represents s_bytes || salt
    bytes: std.ArrayList(u8),
    allocator: Allocator,
    pub fn new(allocator: Allocator, initial_bytes: []const u8) !Signature {
        var list = std.ArrayList(u8).init(allocator);
        errdefer if(list.items.len ==0 and initial_bytes.len > 0) list.deinit();
        try list.appendSlice(initial_bytes);
        return .{ .bytes = list, .allocator = allocator };
    }
    pub fn deinit(self: *Signature) void { self.bytes.deinit(); }
    pub fn get_bytes(self: Signature) []const u8 { return self.bytes.items; }
    pub fn clone(self: Signature) !Signature {
        return Signature.new(self.allocator, self.bytes.items);
    }
};

pub const Message = struct {
    bytes: std.ArrayList(u8),
    allocator: Allocator,
    pub fn new(allocator: Allocator, initial_bytes: []const u8) !Message {
        var list = std.ArrayList(u8).init(allocator);
        errdefer if(list.items.len ==0 and initial_bytes.len > 0) list.deinit();
        try list.appendSlice(initial_bytes);
        return .{ .bytes = list, .allocator = allocator };
    }
    pub fn deinit(self: *Message) void { self.bytes.deinit(); }
    pub fn get_bytes(self: Message) []const u8 { return self.bytes.items; }
    pub fn clone(self: Message) !Message {
        return Message.new(self.allocator, self.bytes.items);
    }
};

pub const MessageDigest = struct {
    bytes: std.ArrayList(u8),
    allocator: Allocator,
    pub fn new(allocator: Allocator, initial_bytes: []const u8) !MessageDigest {
        var list = std.ArrayList(u8).init(allocator);
        errdefer if(list.items.len ==0 and initial_bytes.len > 0) list.deinit();
        try list.appendSlice(initial_bytes);
        return .{ .bytes = list, .allocator = allocator };
    }
    pub fn deinit(self: *MessageDigest) void { self.bytes.deinit(); }
    pub fn get_bytes(self: MessageDigest) []const u8 { return self.bytes.items; }
    pub fn clone(self: MessageDigest) !MessageDigest {
        return MessageDigest.new(self.allocator, self.bytes.items);
    }
};

pub const Salt = struct {
    bytes: std.ArrayList(u8),
    allocator: Allocator,
    pub fn new(allocator: Allocator, initial_bytes: []const u8) !Salt {
        var list = std.ArrayList(u8).init(allocator);
        errdefer if(list.items.len ==0 and initial_bytes.len > 0) list.deinit();
        try list.appendSlice(initial_bytes);
        return .{ .bytes = list, .allocator = allocator };
    }
    pub fn deinit(self: *Salt) void { self.bytes.deinit(); }
    pub fn get_bytes(self: Salt) []const u8 { return self.bytes.items; }
    pub fn clone(self: Salt) !Salt {
        return Salt.new(self.allocator, self.bytes.items);
    }
};

// Basic tests for type construction and deinitialization
test "GFElement" {
    const elem = GFElement.new(10);
    try std.testing.expectEqual(@as(u8, 10), elem.value());
    const elem2 = GFElement.new(15);
    try std.testing.expectEqual(@as(u8, 15), elem2.value());
    // Test truncation if values > 15 are passed, though u4 should handle it.
    // const elem_trunc = GFElement.new(16); // This would be a compile error if val:u4
    // try std.testing.expectEqual(@as(u8, 0), elem_trunc.value());
}

test "GFVector basic" {
    var vec = GFVector.init(std.testing.allocator);
    defer vec.deinit();
    try vec.append(GFElement.new(1));
    try vec.append(GFElement.new(2));
    try std.testing.expectEqual(@as(usize, 2), vec.items.len);
    try std.testing.expectEqual(@as(u8, 1), vec.items[0].value());
}

test "GFMatrix basic" {
    var matrix = try GFMatrix.new(std.testing.allocator, 2, 3);
    defer matrix.deinit();

    try std.testing.expectEqual(@as(usize, 2), matrix.rows);
    try std.testing.expectEqual(@as(usize, 3), matrix.cols);
    try std.testing.expectEqual(@as(usize, 6), matrix.data.items.len);

    matrix.set(0, 0, GFElement.new(5));
    const val = matrix.get(0,0).?;
    try std.testing.expectEqual(@as(u8, 5), val.value());

    const val_none = matrix.get(3,3);
    try std.testing.expect(val_none == null);
}

test "Byte-wrapper types basic" {
    var csk = try CompactSecretKey.new(std.testing.allocator, &[_]u8{1,2,3});
    defer csk.deinit();
    try std.testing.expectEqualSlices(u8, &[_]u8{1,2,3}, csk.get_bytes());

    var cpk = try CompactPublicKey.new(std.testing.allocator, &[_]u8{4,5,6});
    defer cpk.deinit();
    var cpk_clone = try cpk.clone();
    defer cpk_clone.deinit();
    try std.testing.expectEqualSlices(u8, &[_]u8{4,5,6}, cpk_clone.get_bytes());

    // Test one more for good measure
    var sig = try Signature.new(std.testing.allocator, &[_]u8{7,8});
    defer sig.deinit();
    try std.testing.expectEqualSlices(u8, &[_]u8{7,8}, sig.get_bytes());
}
