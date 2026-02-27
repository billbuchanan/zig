const std = @import("std");

const c = @cImport({
    @cInclude("openssl/evp.h");
    @cInclude("openssl/kdf.h");
    @cInclude("openssl/params.h");
    @cInclude("openssl/core_names.h");
    @cInclude("openssl/err.h");
});

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    const password = args[1];

    //   const cipher: []const u8 = "AES-128-CBC";
    const cipher = args[2];

    var out_len: usize = 0;

    const mac = c.EVP_MAC_fetch(null, "CMAC", null) orelse return error.MacFetchFailed;
    defer c.EVP_MAC_free(mac);

    const ctx = c.EVP_MAC_CTX_new(mac) orelse return error.MacCtxNewFailed;
    defer c.EVP_MAC_CTX_free(ctx);
    var params: [2]c.OSSL_PARAM = undefined;

    params[0] = c.OSSL_PARAM_construct_utf8_string(c.OSSL_MAC_PARAM_CIPHER, @ptrCast(@constCast(cipher)), cipher.len);
    params[1] = c.OSSL_PARAM_construct_end();

    var key_size: usize = 32; // 256 bit key
    if (std.mem.indexOf(u8, cipher, "128") != null) {
        key_size = 16;
    }
    if (std.mem.indexOf(u8, cipher, "192") != null) {
        key_size = 24;
    }
    const key = try allocator.alloc(u8, key_size);
    defer allocator.free(key);
    std.crypto.random.bytes(key);

    const dk_size = 4096;
    const dk = try allocator.alloc(u8, dk_size);
    defer allocator.free(dk);

    if (c.EVP_MAC_init(ctx, key.ptr, key.len, &params[0]) != 1) return error.MacInitFailed;
    if (c.EVP_MAC_update(ctx, password.ptr, password.len) != 1) return error.MacUpdateFailed;

    if (c.EVP_MAC_final(ctx, dk.ptr, &out_len, dk.len) != 1) return error.MacFinalFailed;

    try stdout.print("\nCMAC\n", .{});

    try stdout.print("\nData: {s}\n", .{password});

    try stdout.print("\nKey: {x}\n", .{key});

    try stdout.print("\nCMAC (CMAC-{s}): {x}\n", .{ cipher, dk[0..out_len] });
    try stdout.flush();
}
