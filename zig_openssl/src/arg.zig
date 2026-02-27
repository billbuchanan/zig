const std = @import("std");

const c = @cImport({
    @cInclude("openssl/evp.h");
    @cInclude("openssl/kdf.h");
    @cInclude("openssl/params.h");
    @cInclude("openssl/core_names.h");
    @cInclude("openssl/thread.h");
    @cInclude("openssl/err.h");
});

fn opensslErrString(buf: []u8) []const u8 {
    const code = c.ERR_get_error();
    if (code == 0) return "no OpenSSL error";
    _ = c.ERR_error_string_n(code, buf.ptr, buf.len);
    const nul = std.mem.indexOfScalar(u8, buf, 0) orelse buf.len;
    return buf[0..nul];
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    var password: []u8 = undefined;
    var salt: []u8 = undefined;

    var mode: [:0]const u8 = "ARGON2ID";
    var memcost: u32 = 1024; // 64 MiB (1KiB blocks)
    var iter: u32 = 3;
    var lanes: u32 = 2;
    var threads: u32 = 1;

    var dk_len: usize = 32;

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    // Check if there are any arguments
    if (args.len > 1) {
        password = args[1];
    }
    if (args.len > 2) {
        salt = args[2];
    }
    if (args.len > 3) {
        mode = args[3];
    }
    if (args.len > 4) {
        iter = try std.fmt.parseInt(u32, args[4], 10);
    }
    if (args.len > 5) {
        lanes = try std.fmt.parseInt(u32, args[5], 10);
    }
    if (args.len > 6) {
        threads = try std.fmt.parseInt(u32, args[6], 10);
    }
    if (args.len > 7) {
        memcost = try std.fmt.parseInt(u32, args[7], 10);
    }
    if (args.len > 8) {
        dk_len = try std.fmt.parseInt(u32, args[8], 10);
    }

    const dk = try allocator.alloc(u8, dk_len);
    defer allocator.free(dk);

    var params: [7]c.OSSL_PARAM = undefined;
    params[0] = c.OSSL_PARAM_construct_uint32(c.OSSL_KDF_PARAM_THREADS, &threads);
    params[1] = c.OSSL_PARAM_construct_uint32(c.OSSL_KDF_PARAM_ARGON2_LANES, &lanes);
    params[2] = c.OSSL_PARAM_construct_uint32(c.OSSL_KDF_PARAM_ARGON2_MEMCOST, &memcost);
    params[3] = c.OSSL_PARAM_construct_uint32(c.OSSL_KDF_PARAM_ITER, &iter);

    params[4] = c.OSSL_PARAM_construct_octet_string(
        c.OSSL_KDF_PARAM_SALT,
        @ptrCast(@constCast(salt.ptr)),
        salt.len,
    );
    params[5] = c.OSSL_PARAM_construct_octet_string(
        c.OSSL_KDF_PARAM_PASSWORD,
        @ptrCast(@constCast(password.ptr)),
        password.len,
    );
    params[6] = c.OSSL_PARAM_construct_end();

    const kdf = c.EVP_KDF_fetch(null, mode.ptr, null);
    defer c.EVP_KDF_free(kdf);

    const kctx = c.EVP_KDF_CTX_new(kdf);
    defer c.EVP_KDF_CTX_free(kctx);

    const ok = c.EVP_KDF_derive(kctx, dk.ptr, &params[0]);

    if (ok != 1) {
        var eb: [256]u8 = undefined;
        try stdout.print("EVP_KDF_derive failed: {s}\n", .{opensslErrString(&eb)});
        try stdout.flush();
        return;
    }
    try stdout.print("{s} OpenSSL integration with Zig\n", .{mode});
    try stdout.print("Password: {s}, Salt: {s}\n", .{ password, salt });

    try stdout.print("\nIterations: {d}, Lanes (Parallelism): {d}, Threads: {d}, Memcost {d}\n", .{ iter, lanes, threads, memcost });
    try stdout.print("\nHash: {x}\n", .{dk});

    try stdout.flush();
}
