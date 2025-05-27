const std = @import("std");
const mem = std.mem;
const fs = std.fs;
const process = std.process;
const fmt = std.fmt;
const ArrayList = std.ArrayList;

// Adjust path to the main library based on actual project structure
// Assuming 'mayo_lib' is the name of the library in build.zig
const mayo_api = @import("../../src/api.zig");
const mayo_types = @import("../../src/types.zig"); // For potential direct use of types if needed

const Allocator = std.mem.Allocator;

// --- Helper Functions ---

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

fn bytes_to_hex_string(allocator: Allocator, bytes: []const u8) ![]u8 {
    var hex_chars = try allocator.alloc(u8, bytes.len * 2);
    errdefer allocator.free(hex_chars);
    for (bytes, 0..) |byte, i| {
        hex_chars[i * 2] = fmt.hex_digit_table_lower[byte >> 4];
        hex_chars[i * 2 + 1] = fmt.hex_digit_table_lower[byte & 0x0F];
    }
    return hex_chars;
}

fn read_file_alloc(allocator: Allocator, path: []const u8, max_size: usize) !ArrayList(u8) {
    const file = try fs.cwd().openFile(path, .{ .mode = .read_only });
    defer file.close();
    const contents = try file.readToEndAlloc(allocator, max_size);
    errdefer allocator.free(contents);
    return ArrayList(u8).init_slice_clone(allocator, contents);
}

fn write_file(path: []const u8, data: []const u8) !void {
    const file = try fs.cwd().createFile(path, .{ .read = true }); // .read = true for default mode
    defer file.close();
    try file.writeAll(data);
}

fn read_stdin_alloc(allocator: Allocator, max_size: usize) !ArrayList(u8) {
    const stdin_file = std.io.getStdIn();
    const contents = try stdin_file.readToEndAlloc(allocator, max_size);
    errdefer allocator.free(contents);
    return ArrayList(u8).init_slice_clone(allocator, contents);
}

const CliError = error{
    InvalidArguments,
    MissingArgument,
    FileIOError,
    HexCodingError,
    ApiError, // General wrapper for errors from mayo_api
    UnknownMayoVariant,
    AllocationFailed,
} || mayo_api.ApiError; // Include ApiError variants directly

// --- Subcommands ---

fn keygen_subcommand(allocator: Allocator, args: *process.ArgIterator) !void {
    var variant_name: ?[]const u8 = null;
    var sk_path: ?[]const u8 = null;
    var pk_path: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (mem.eql(u8, arg, "--variant")) {
            variant_name = args.next() orelse return CliError.MissingArgument;
        } else if (mem.eql(u8, arg, "--sk")) {
            sk_path = args.next() orelse return CliError.MissingArgument;
        } else if (mem.eql(u8, arg, "--pk")) {
            pk_path = args.next() orelse return CliError.MissingArgument;
        } else {
            std.io.getStdErr().writer().print("Unknown argument for keygen: {s}\n", .{arg}) catch {};
            return CliError.InvalidArguments;
        }
    }

    if (variant_name == null or sk_path == null or pk_path == null) {
        std.io.getStdErr().writer().print("Usage: mayo-cli keygen --variant <name> --sk <sk_file> --pk <pk_file>\n", .{}) catch {};
        return CliError.MissingArgument;
    }

    var keypair = try mayo_api.keypair(allocator, variant_name.?);
    defer keypair.deinit();

    try write_file(sk_path.?, keypair.sk.bytes.items) catch |e| {
        std.io.getStdErr().writer().print("Failed to write secret key to {s}: {any}\n", .{sk_path.?, e}) catch {};
        return CliError.FileIOError;
    };
    try write_file(pk_path.?, keypair.pk.bytes.items) catch |e| {
        std.io.getStdErr().writer().print("Failed to write public key to {s}: {any}\n", .{pk_path.?, e}) catch {};
        return CliError.FileIOError;
    };

    std.io.getStdOut().writer().print("Keys generated successfully.\nSK: {s}\nPK: {s}\n", .{sk_path.?, pk_path.?}) catch {};
}

fn sign_subcommand(allocator: Allocator, args: *process.ArgIterator) !void {
    var variant_name: ?[]const u8 = null;
    var sk_path: ?[]const u8 = null;
    var in_path: ?[]const u8 = null;
    var sig_path: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (mem.eql(u8, arg, "--variant")) {
            variant_name = args.next() orelse return CliError.MissingArgument;
        } else if (mem.eql(u8, arg, "--sk")) {
            sk_path = args.next() orelse return CliError.MissingArgument;
        } else if (mem.eql(u8, arg, "--in")) {
            in_path = args.next() orelse return CliError.MissingArgument;
        } else if (mem.eql(u8, arg, "--sig")) {
            sig_path = args.next() orelse return CliError.MissingArgument;
        } else {
             std.io.getStdErr().writer().print("Unknown argument for sign: {s}\n", .{arg}) catch {};
            return CliError.InvalidArguments;
        }
    }
    
    if (variant_name == null or sk_path == null or in_path == null or sig_path == null) {
        std.io.getStdErr().writer().print("Usage: mayo-cli sign --variant <name> --sk <sk_file> --in <msg_file|-> --sig <sig_file|->\n", .{}) catch {};
        return CliError.MissingArgument;
    }

    var sk_data = try read_file_alloc(allocator, sk_path.?, 1_000_000) catch |e| {
        std.io.getStdErr().writer().print("Failed to read secret key from {s}: {any}\n", .{sk_path.?, e}) catch {};
        return CliError.FileIOError;
    };
    defer sk_data.deinit();

    var msg_data: ArrayList(u8) = undefined;
    if (mem.eql(u8, in_path.?, "-")) {
        msg_data = try read_stdin_alloc(allocator, 1_000_000) catch |e| {
            std.io.getStdErr().writer().print("Failed to read message from stdin: {any}\n", .{e}) catch {};
            return CliError.FileIOError;
        };
    } else {
        msg_data = try read_file_alloc(allocator, in_path.?, 1_000_000) catch |e| {
            std.io.getStdErr().writer().print("Failed to read message from {s}: {any}\n", .{in_path.?, e}) catch {};
            return CliError.FileIOError;
        };
    }
    defer msg_data.deinit();

    var signature_bytes = try mayo_api.sign(allocator, sk_data.items, msg_data.items, variant_name.?);
    defer signature_bytes.deinit();

    if (mem.eql(u8, sig_path.?, "-")) {
        var hex_sig = try bytes_to_hex_string(allocator, signature_bytes.items);
        defer allocator.free(hex_sig);
        try std.io.getStdOut().writer().print("{s}\n", .{hex_sig});
    } else {
        try write_file(sig_path.?, signature_bytes.items) catch |e| {
            std.io.getStdErr().writer().print("Failed to write signature to {s}: {any}\n", .{sig_path.?, e}) catch {};
            return CliError.FileIOError;
        };
        std.io.getStdOut().writer().print("Message signed. Signature saved to {s}\n", .{sig_path.?}) catch {};
    }
}

fn verify_subcommand(allocator: Allocator, args: *process.ArgIterator) !void {
    var variant_name: ?[]const u8 = null;
    var pk_path: ?[]const u8 = null;
    var in_path: ?[]const u8 = null;
    var sig_path: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (mem.eql(u8, arg, "--variant")) {
            variant_name = args.next() orelse return CliError.MissingArgument;
        } else if (mem.eql(u8, arg, "--pk")) {
            pk_path = args.next() orelse return CliError.MissingArgument;
        } else if (mem.eql(u8, arg, "--in")) {
            in_path = args.next() orelse return CliError.MissingArgument;
        } else if (mem.eql(u8, arg, "--sig")) {
            sig_path = args.next() orelse return CliError.MissingArgument;
        } else {
            std.io.getStdErr().writer().print("Unknown argument for verify: {s}\n", .{arg}) catch {};
            return CliError.InvalidArguments;
        }
    }

    if (variant_name == null or pk_path == null or in_path == null or sig_path == null) {
        std.io.getStdErr().writer().print("Usage: mayo-cli verify --variant <name> --pk <pk_file> --in <msg_file|-> --sig <sig_file|->\n", .{}) catch {};
        return CliError.MissingArgument;
    }

    var pk_data = try read_file_alloc(allocator, pk_path.?, 1_000_000) catch |e| {
        std.io.getStdErr().writer().print("Failed to read public key from {s}: {any}\n", .{pk_path.?, e}) catch {};
        return CliError.FileIOError;
    };
    defer pk_data.deinit();

    var msg_data: ArrayList(u8) = undefined;
    if (mem.eql(u8, in_path.?, "-")) {
        msg_data = try read_stdin_alloc(allocator, 1_000_000) catch |e| {
             std.io.getStdErr().writer().print("Failed to read message from stdin: {any}\n", .{e}) catch {};
            return CliError.FileIOError;
        };
    } else {
        msg_data = try read_file_alloc(allocator, in_path.?, 1_000_000) catch |e| {
            std.io.getStdErr().writer().print("Failed to read message from {s}: {any}\n", .{in_path.?, e}) catch {};
            return CliError.FileIOError;
        };
    }
    defer msg_data.deinit();

    var sig_data: ArrayList(u8) = undefined;
    if (mem.eql(u8, sig_path.?, "-")) {
        var hex_sig_stdin = try read_stdin_alloc(allocator, 1_000_000) catch |e| { // Max hex sig length
            std.io.getStdErr().writer().print("Failed to read signature from stdin: {any}\n", .{e}) catch {};
            return CliError.FileIOError;
        };
        defer hex_sig_stdin.deinit();
        const trimmed_hex_sig = mem.trim(u8, hex_sig_stdin.items, " \r\n");
        sig_data = try hex_string_to_bytes(allocator, trimmed_hex_sig) catch |e| {
            std.io.getStdErr().writer().print("Failed to decode hex signature from stdin: {any}\n", .{e}) catch {};
            return CliError.HexCodingError;
        };
    } else {
        sig_data = try read_file_alloc(allocator, sig_path.?, 1_000_000) catch |e| {
            std.io.getStdErr().writer().print("Failed to read signature from {s}: {any}\n", .{sig_path.?, e}) catch {};
            return CliError.FileIOError;
        };
    }
    defer sig_data.deinit();

    // Construct signed_message_bytes = signature_bytes || message_bytes
    var signed_msg_list = ArrayList(u8).init(allocator);
    defer signed_msg_list.deinit();
    try signed_msg_list.appendSlice(sig_data.items);
    try signed_msg_list.appendSlice(msg_data.items);
    
    const opened_message_opt = try mayo_api.open(allocator, pk_data.items, signed_msg_list.items, variant_name.?);

    if (opened_message_opt) |opened_msg| {
        defer opened_msg.deinit();
        // Optionally compare opened_msg.items with msg_data.items if needed, but api.open implies it matches.
        std.io.getStdOut().writer().print("Verification OK.\n", .{}) catch {};
    } else {
        std.io.getStdErr().writer().print("Verification FAILED.\n", .{}) catch {};
    }
}


pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit(); // Ensure all memory is freed at the end

    var args = try process.argsAlloc(allocator);
    defer process.argsFree(allocator, args);

    var arg_iter = process.ArgIterator{ .args = args };
    _ = arg_iter.next(); // Skip executable name

    const subcommand = arg_iter.next() orelse {
        try std.io.getStdErr().writer().print(
            \\Usage: mayo-cli <keygen|sign|verify> [options]
            \\
            \\Subcommands:
            \\  keygen   Generate a new keypair.
            \\  sign     Sign a message.
            \\  verify   Verify a signature and recover the message.
            \\
            \\Run mayo-cli <subcommand> --help for more details (not implemented).
            \\
        , .{});
        return;
    };

    if (mem.eql(u8, subcommand, "keygen")) {
        try keygen_subcommand(allocator, &arg_iter);
    } else if (mem.eql(u8, subcommand, "sign")) {
        try sign_subcommand(allocator, &arg_iter);
    } else if (mem.eql(u8, subcommand, "verify")) {
        try verify_subcommand(allocator, &arg_iter);
    } else {
        std.io.getStdErr().writer().print("Unknown subcommand: {s}\n", .{subcommand}) catch {};
        return CliError.InvalidArguments;
    }
}
```
