// mayo-zig/src/lib.zig
// This file will be the main library entry point, exporting public APIs and modules.

const std = @import("std");

// Publicly export modules and/or specific functions from the API.
// For example:
// pub const api = @import("api.zig");
// pub const MayoParams = @import("params.zig").MayoParams;
// pub const keypair = api.keypair;
// pub const sign = api.sign;
// pub const verify = api.verify; // or api.open

// TODO: Add more specific exports as the library develops.

test "lib module placeholder" {
    std.debug.print("Lib module tests will go here. (Likely integration tests)\n", .{});
    try std.testing.expect(true);
}
