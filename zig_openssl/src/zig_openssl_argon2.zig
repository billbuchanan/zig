const std = @import("std");

const c = @cImport({
    @cInclude("openssl/evp.h");
    @cInclude("openssl/kdf.h");
    @cInclude("openssl/params.h");
    @cInclude("openssl/core_names.h");
    @cInclude("openssl/thread.h");
    @cInclude("openssl/err.h");
});
fn hexPrint(w: anytype, bytes: []const u8) !void {
    for (bytes) |b| try w.print("{x:0>2}", .{b});
    try w.writeByte('\n');
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    const password = "Hello";
    const salt = "salt";

    const mode: [:0]const u8 = "ARGON2ID";
    var memcost: u32 = 65536; // 64 MiB (in 1 KiB blocks)
    var iter: u32 = 3;
    var lanes: u32 = 2;
    var threads: u32 = 2;

    const dk_len: u32 = 32;
    const salt_len: usize = salt.len;
    const password_len: usize = password.len;

    const dk = try allocator.alloc(u8, dk_len);
    defer allocator.free(dk);

    var params: [7]c.OSSL_PARAM = undefined;

    // threads, lanes, memcost, iter
    params[0] = c.OSSL_PARAM_construct_uint32(c.OSSL_KDF_PARAM_THREADS, &threads);

    params[1] = c.OSSL_PARAM_construct_uint32(c.OSSL_KDF_PARAM_ARGON2_LANES, &lanes);

    params[2] = c.OSSL_PARAM_construct_uint32(c.OSSL_KDF_PARAM_ARGON2_MEMCOST, &memcost);

    params[3] = c.OSSL_PARAM_construct_uint32(c.OSSL_KDF_PARAM_ITER, &iter);

    // salt, password as octet strings
    params[4] = c.OSSL_PARAM_construct_octet_string(c.OSSL_KDF_PARAM_SALT, @ptrCast(@constCast(salt.ptr)), salt_len);

    params[5] = c.OSSL_PARAM_construct_octet_string(c.OSSL_KDF_PARAM_PASSWORD, @ptrCast(@constCast(password.ptr)), password_len);
    params[6] = c.OSSL_PARAM_construct_end();

    // Fetch + derive
    const kdf = c.EVP_KDF_fetch(null, mode.ptr, null);
    defer c.EVP_KDF_free(kdf);

    const kctx = c.EVP_KDF_CTX_new(kdf);
    defer c.EVP_KDF_CTX_free(kctx);

    _ = c.EVP_KDF_derive(kctx, dk.ptr, dk.len, &params[0]);

    try stdout.print("Zig interface with OpenSSL. Argon2\n\n", .{});
    try stdout.print("Password:\t{s}\n", .{password});
    try stdout.print("Salt:\t\t{s}\n\n", .{salt});
    try stdout.print("Argon2:\t\t{x}\n\n", .{dk});
    try stdout.print("Password len:\t\t{d}\n\n", .{password_len});
    try hexPrint(stdout, dk);
    try stdout.flush();
}
