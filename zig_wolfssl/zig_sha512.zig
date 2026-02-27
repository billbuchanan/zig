const std = @import("std");

const c = @cImport({
    @cInclude("wolfssl/wolfcrypt/options.h");
    @cInclude("wolfssl/wolfcrypt/settings.h");
    @cInclude("wolfssl/wolfcrypt/types.h");
    @cInclude("wolfssl/wolfcrypt/sha512.h");
    @cInclude("wolfssl/wolfcrypt/error-crypt.h");
});

fn wcOk(ret: c_int, what: []const u8) !void {
    if (ret == 0) return;
    std.debug.print("{s} failed: {d}\n", .{ what, ret });
    return error.WolfCryptError;
}

pub fn main() !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    const msg = "hello";

    if (!@hasDecl(c, "Sha512")) {
        std.debug.print("SHA-512 not enabled in this wolfSSL build (Sha512 type missing)\n", .{});
        return;
    }

    var sha512: c.Sha512 = undefined;
    try wcOk(c.wc_InitSha512(&sha512), "wc_InitSha512");
    defer _ = c.wc_Sha512Free(&sha512);

    try wcOk(c.wc_Sha512Update(&sha512, msg.ptr, @intCast(msg.len)), "wc_Sha512Update");

    var digest: [c.SHA512_DIGEST_SIZE]u8 = undefined;
    try wcOk(c.wc_Sha512Final(&sha512, &digest), "wc_Sha512Final");

    try stdout.print("SHA-512 digest size: {d}\n", .{digest.len});

    try stdout.flush();
}
