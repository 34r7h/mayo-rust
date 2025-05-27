const std = @import("std");
const testing = std.testing;
const mem = std.mem;
const fs = std.fs;
const fmt = std.fmt;
const ArrayList = std.ArrayList;

const api = @import("../src/api.zig"); 
const types = @import("../src/types.zig"); 
const params_mod = @import("../src/params.zig"); // For MayoParams.get_params_by_name

const Allocator = std.mem.Allocator;

// --- Helper Functions for KAT Parsing ---

fn hex_char_to_u4(hex_char: u8) !u4 {
    return switch (hex_char) {
        '0'...'9' => @intCast(u4, hex_char - '0'),
        'a'...'f' => @intCast(u4, hex_char - 'a' + 10),
        'A'...'F' => @intCast(u4, hex_char - 'A' + 10),
        else => error.InvalidHexChar,
    };
}

fn hex_string_to_bytes(allocator: Allocator, hex_str: []const u8) !ArrayList(u8) {
    if (hex_str.len % 2 != 0) return error.InvalidHexStringLength;

    var bytes_list = ArrayList(u8).init(allocator);
    errdefer bytes_list.deinit();

    var i: usize = 0;
    while (i < hex_str.len) : (i += 2) {
        const hi_nibble = try hex_char_to_u4(hex_str[i]);
        const lo_nibble = try hex_char_to_u4(hex_str[i + 1]);
        try bytes_list.append((hi_nibble << 4) | lo_nibble);
    }
    return bytes_list;
}

fn parse_kat_line_hex_value(
    allocator: Allocator,
    line: []const u8,
    prefix: []const u8,
) !?ArrayList(u8) {
    if (!mem.startsWith(u8, line, prefix)) {
        return null;
    }
    var parts = mem.splitScalar(u8, line, '=');
    _ = parts.next() orelse return error.KatFileParseError; 
    const hex_value_trimmed = mem.trim(u8, parts.next() orelse return error.KatFileParseError, " \r\n");
    
    if (hex_value_trimmed.len == 0) {
        return ArrayList(u8).init(allocator);
    }
    return hex_string_to_bytes(allocator, hex_value_trimmed);
}

const KatReqData = struct {
    msg: ArrayList(u8),

    fn deinit(self: KatReqData) void {
        self.msg.deinit();
    }
};

const KatRspData = struct {
    pk: ArrayList(u8),
    sk: ArrayList(u8),
    sm: ArrayList(u8),

    fn deinit(self: KatRspData) void {
        self.pk.deinit();
        self.sk.deinit();
        self.sm.deinit();
    }
};

fn read_and_parse_req_file(allocator: Allocator, filepath: []const u8) !KatReqData {
    const file_contents = try fs.cwd().readFileAlloc(allocator, filepath, 1_000_000); 
    defer allocator.free(file_contents);

    var msg_list: ?ArrayList(u8) = null;
    defer if (msg_list) |ml| ml.deinit();

    var lines = mem.splitScalar(u8, file_contents, '\n');
    while (lines.next()) |line_raw| {
        const line = mem.trimRight(u8, line_raw, "\r"); // Handle CRLF
        if (mem.startsWith(u8, line, "#") or mem.trim(u8, line, " ").len == 0) continue;

        if (msg_list == null) {
            msg_list = try parse_kat_line_hex_value(allocator, line, "msg = ");
            if (msg_list != null) continue;
        }
    }

    if (msg_list == null) return error.KatFileMissingData;
    
    var data = KatReqData{ .msg = msg_list.? };
    msg_list = null; 
    return data;
}

fn read_and_parse_rsp_file(allocator: Allocator, filepath: []const u8) !KatRspData {
    const file_contents = try fs.cwd().readFileAlloc(allocator, filepath, 1_000_000);
    defer allocator.free(file_contents);

    var pk_list: ?ArrayList(u8) = null;
    defer if (pk_list) |l| l.deinit();
    var sk_list: ?ArrayList(u8) = null;
    defer if (sk_list) |l| l.deinit();
    var sm_list: ?ArrayList(u8) = null;
    defer if (sm_list) |l| l.deinit();

    var lines = mem.splitScalar(u8, file_contents, '\n');
    while (lines.next()) |line_raw| {
        const line = mem.trimRight(u8, line_raw, "\r"); // Handle CRLF
        if (mem.startsWith(u8, line, "#") or mem.trim(u8, line, " ").len == 0) continue;

        if (pk_list == null) {
            pk_list = try parse_kat_line_hex_value(allocator, line, "pk = ");
            if (pk_list != null) continue;
        }
        if (sk_list == null) {
            sk_list = try parse_kat_line_hex_value(allocator, line, "sk = ");
            if (sk_list != null) continue;
        }
        if (sm_list == null) {
            sm_list = try parse_kat_line_hex_value(allocator, line, "sm = ");
            if (sm_list != null) continue;
        }
    }

    if (pk_list == null or sk_list == null or sm_list == null) return error.KatFileMissingData;

    var data = KatRspData {
        .pk = pk_list.?,
        .sk = sk_list.?,
        .sm = sm_list.?,
    };
    pk_list = null; sk_list = null; sm_list = null; 
    return data;
}

// --- Test Definitions ---

const KatFileSet = struct {
    req_suffix: []const u8,
    rsp_suffix: []const u8,
    variant_name: []const u8, 
    kat_base_path: []const u8 = "MAYO-C-main/KAT/",
};

// Updated variant names based on task description
const kat_file_sets = [_]KatFileSet{
    KatFileSet{ .req_suffix = "PQCsignKAT_24_MAYO_1.req", .rsp_suffix = "PQCsignKAT_24_MAYO_1.rsp", .variant_name = "MAYO1_L1" },
    KatFileSet{ .req_suffix = "PQCsignKAT_24_MAYO_2.req", .rsp_suffix = "PQCsignKAT_24_MAYO_2.rsp", .variant_name = "MAYO2_L3" },
    // Add other L-levels for MAYO1 and MAYO2 if their params are defined in params.zig
    // e.g. "MAYO1_L3", "MAYO1_L5", "MAYO2_L1", "MAYO2_L5"
    // For now, limiting to one L-level per MAYO_X group from prompt.
};

test "MAYO Known Answer Tests (Sign/Open)" {
    const allocator = testing.allocator;

    for (kat_file_sets) |kat_set| {
        const params_enum_opt = params_mod.MayoParams.get_params_by_name(kat_set.variant_name);
        if (params_enum_opt == null) {
            std.debug.print("\nSkipping KAT for {s} ({s}): Variant name not found in params_mod.MayoParams mapping.\n", .{kat_set.req_suffix, kat_set.variant_name});
            continue;
        }
        // const params_variant = params_enum_opt.?.variant(); // Not directly used here, but good check

        std.debug.print("\nProcessing KAT: {s} and {s} for variant {s}\n", .{
            kat_set.req_suffix, kat_set.rsp_suffix, kat_set.variant_name
        });

        const req_file_path = try std.fmt.allocPrint(allocator, "{s}{s}", .{kat_set.kat_base_path, kat_set.req_suffix});
        defer allocator.free(req_file_path);
        const rsp_file_path = try std.fmt.allocPrint(allocator, "{s}{s}", .{kat_set.kat_base_path, kat_set.rsp_suffix});
        defer allocator.free(rsp_file_path);

        var req_data = try read_and_parse_req_file(allocator, req_file_path);
        defer req_data.deinit();

        var rsp_data = try read_and_parse_rsp_file(allocator, rsp_file_path);
        defer rsp_data.deinit();
        
        std.debug.print("  Msg len: {}, SK len: {}, PK len: {}, SM len: {}\n", .{
            req_data.msg.items.len, rsp_data.sk.items.len, rsp_data.pk.items.len, rsp_data.sm.items.len
        });

        // Test api.sign
        std.debug.print("  Testing api.sign for {s}...\n", .{kat_set.variant_name});
        var generated_sig_list = try api.sign(allocator, rsp_data.sk.items, req_data.msg.items, kat_set.variant_name);
        defer generated_sig_list.deinit();

        var generated_sm_list = ArrayList(u8).init(allocator);
        defer generated_sm_list.deinit();
        try generated_sm_list.appendSlice(generated_sig_list.items);
        try generated_sm_list.appendSlice(req_data.msg.items);

        try testing.expectEqualSlices(u8, rsp_data.sm.items, generated_sm_list.items);
        std.debug.print("  api.sign successful for {s}.\n", .{kat_set.variant_name});

        // Test api.open (valid signature)
        std.debug.print("  Testing api.open (valid) for {s}...\n", .{kat_set.variant_name});
        var opened_msg_list_opt = try api.open(allocator, rsp_data.pk.items, rsp_data.sm.items, kat_set.variant_name);
        
        try testing.expect(opened_msg_list_opt != null); // Expect successful opening
        if (opened_msg_list_opt) |opened_msg_list| {
            defer opened_msg_list.deinit();
            try testing.expectEqualSlices(u8, req_data.msg.items, opened_msg_list.items);
            std.debug.print("  api.open (valid) successful for {s}.\n", .{kat_set.variant_name});
        } else {
             std.debug.print("  api.open (valid) FAILED for {s} - returned null.\n", .{kat_set.variant_name});
             try testing.expect(false); // Force failure if null
        }


        // Test api.open (tampered signature)
        std.debug.print("  Testing api.open (tampered) for {s}...\n", .{kat_set.variant_name});
        var tampered_sm_list = try rsp_data.sm.clone(); 
        defer tampered_sm_list.deinit();
        
        if (tampered_sm_list.items.len > 0) {
            // Tamper the signature part. Signature is at the beginning of 'sm'.
            tampered_sm_list.items[0] +%= 1; 
        } else {
            // This case should ideally not happen for valid KAT files.
            // If sm is empty, make it non-empty and thus invalid.
            try tampered_sm_list.append(0xAA);
        }
        
        var opened_tampered_msg_opt = try api.open(allocator, rsp_data.pk.items, tampered_sm_list.items, kat_set.variant_name);
        try testing.expect(opened_tampered_msg_opt == null); // Expect tampered signature to fail opening
        if (opened_tampered_msg_opt != null) {
             std.debug.print("  api.open (tampered) FAILED for {s} - expected null but got a message.\n", .{kat_set.variant_name});
             opened_tampered_msg_opt.?.deinit(); // Clean up if it unexpectedly returned something
             try testing.expect(false); 
        } else {
            std.debug.print("  api.open (tampered) successful (verification failed as expected) for {s}.\n", .{kat_set.variant_name});
        }
    }
}

```
