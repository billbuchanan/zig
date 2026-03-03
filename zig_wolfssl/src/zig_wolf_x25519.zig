// cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DWOLFSSL_RIPEMD=ON -DWOLFSSL_SM3=ON -DWOLFSSL_USER_SETTINGS=yes ..
const std = @import("std");

const c = @cImport({
    @cInclude("wolfssl/wolfcrypt/settings.h");
    @cInclude("wolfssl/wolfcrypt/types.h");
    @cInclude("wolfssl/wolfcrypt/error-crypt.h");

    @cInclude("wolfssl/wolfcrypt/curve25519.h");
});

fn testOkay(ret: c_int, what: []const u8) !void {
    if (ret == 0) return;
    std.debug.print("{s} failed: {d}\n", .{ what, ret });
    return error.WolfCryptError;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Zig 0.15.2 stdout writer pattern
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const msg = args[1];

    try stdout.print("Message: {s}\n\n", .{msg});

    var Alice: c.curve25519_key = undefined;
    _ = c.wc_curve25519_init(&Alice);
    defer c.wc_curve25519_free(&Alice);

    try stdout.flush();
}
