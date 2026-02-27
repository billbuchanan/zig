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

    var mode: []const u8 = "KMAC128";
    mode = args[2];

    var custom: []const u8 = "";
    custom = args[3];

    var out_len: usize = 0;

    const mac = c.EVP_MAC_fetch(null, mode.ptr, null) orelse return error.MacFetchFailed;
    defer c.EVP_MAC_free(mac);

    const ctx = c.EVP_MAC_CTX_new(mac) orelse return error.MacCtxNewFailed;
    defer c.EVP_MAC_CTX_free(ctx);
    var params: [3]c.OSSL_PARAM = undefined;

    const hash = "SHA256";
    params[0] = c.OSSL_PARAM_construct_octet_string(c.OSSL_MAC_PARAM_CUSTOM, @ptrCast(@constCast(custom)), custom.len);
    params[1] = c.OSSL_PARAM_construct_utf8_string(c.OSSL_MAC_PARAM_DIGEST, @ptrCast(@constCast(hash)), 0);

    params[2] = c.OSSL_PARAM_construct_end();

    if (std.mem.indexOf(u8, mode, "SIPHASH") != null) {
        params[0] = c.OSSL_PARAM_construct_end();
    }

    var key_size: usize = 32; // 256 bit key
    if (std.mem.indexOf(u8, mode, "128") != null) {
        key_size = 16;
    }
    if (std.mem.indexOf(u8, mode, "SIPHASH") != null) {
        key_size = 16;
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

    try stdout.print("\nKMAC/Poly1305/SIPHASH\n", .{});

    try stdout.print("\nData: {s}\n", .{password});

    if (std.mem.indexOf(u8, mode, "KMAC") != null) {
        try stdout.print("\nCustom: {s}\n", .{custom});
    }

    try stdout.print("\nKey: {x}\n", .{key});

    try stdout.print("\nMAC ({s}): {x}\n", .{ mode, dk[0..out_len] });
    try stdout.flush();
}
