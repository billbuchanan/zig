const std = @import("std");

const c = @cImport({
    @cInclude("openssl/evp.h");
    @cInclude("openssl/params.h");
    @cInclude("openssl/core_names.h");
    @cInclude("openssl/err.h");
});

fn getBnOct(allocator: std.mem.Allocator, pkey: *c.EVP_PKEY, name: [*c]const u8) ![]u8 {
    var needed: usize = 0;

    if (c.EVP_PKEY_get_octet_string_param(pkey, name, null, 0, &needed) != 1)
        return error.OpenSSLGetSizeFailed;

    var buf = try allocator.alloc(u8, needed);
    errdefer allocator.free(buf);

    var out_len: usize = 0;
    if (c.EVP_PKEY_get_octet_string_param(pkey, name, buf.ptr, buf.len, &out_len) != 1)
        return error.OpenSSLGetValueFailed;

    return buf[0..out_len];
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

    var ml_name: [*c]u8 = undefined; // eg SLH-DSA-SHA2-128f
    var msg: []const u8 = undefined; // eg SLH-DSA-SHA2-128f

    if (args.len > 1) {
        msg = args[1];
    }
    if (args.len > 2) {
        ml_name = args[2];
    }

    const context = c.EVP_PKEY_CTX_new_from_name(null, ml_name, null);

    _ = c.EVP_PKEY_keygen_init(context);
    defer c.EVP_PKEY_CTX_free(context);

    var pkey: ?*c.EVP_PKEY = null;

    _ = c.EVP_PKEY_keygen(context, &pkey);

    const priv = try getBnOct(allocator, pkey.?, c.OSSL_PKEY_PARAM_PRIV_KEY);
    defer allocator.free(priv);

    const public = try getBnOct(allocator, pkey.?, c.OSSL_PKEY_PARAM_PUB_KEY);
    defer allocator.free(public);

    // Now do the signature

    const sig_alg = c.EVP_SIGNATURE_fetch(null, ml_name, null);
    defer c.EVP_SIGNATURE_free(sig_alg);

    // --- Signing context from the key ---
    const sctx = c.EVP_PKEY_CTX_new_from_pkey(null, pkey.?, null);
    defer c.EVP_PKEY_CTX_free(sctx);

    var params: [1]c.OSSL_PARAM = undefined;

    params[0] = c.OSSL_PARAM_construct_end();

    _ = c.EVP_PKEY_sign_message_init(sctx, sig_alg, &params);

    var sig_len: usize = 0;
    _ = c.EVP_PKEY_sign(sctx, null, &sig_len, msg.ptr, msg.len);

    const sig = try allocator.alloc(u8, sig_len);
    defer allocator.free(sig);

    _ = c.EVP_PKEY_sign(sctx, sig.ptr, &sig_len, msg.ptr, msg.len);

    try stdout.print("=== {s} ===\n\n", .{ml_name});
    try stdout.print("Msg: {s}\n", .{msg});
    if (priv.len > 500) {
        try stdout.print("Priv (first 500 bytes) = 0x{x} Length: {d} bytes\n\n", .{ priv[0..500], priv.len });
    } else try stdout.print("Priv = 0x{x} Length: {d} bytes\n\n", .{ priv, priv.len });

    if (public.len > 500) {
        try stdout.print("Public (first 500 bytes) = 0x{x} Length: {d} bytes\n\n", .{ public[0..500], public.len });
    } else try stdout.print("Public = 0x{x} Length: {d} bytes\n\n", .{ public, priv.len });

    if (sig_len > 500) {
        try stdout.print("Signature (first 500 bytes) = 0x{x} Length: {d} bytes\n\n", .{ sig[0..500], sig_len });
    } else try stdout.print("Signature = 0x{x} Length: {d} bytes\n\n", .{ sig, sig_len });

    try stdout.flush();
}
