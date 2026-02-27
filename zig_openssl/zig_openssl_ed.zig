const std = @import("std");

const c = @cImport({
    @cInclude("openssl/evp.h");
    @cInclude("openssl/kdf.h");
    @cInclude("openssl/params.h");
    @cInclude("openssl/core_names.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/ec.h");
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

    const context = c.EVP_PKEY_CTX_new_id(c.EVP_PKEY_ED25519, null);

    _ = c.EVP_PKEY_keygen_init(context);

    var msg: []u8 = undefined;

    if (args.len > 1) {
        msg = args[1];
    }

    var pkey: ?*c.EVP_PKEY = null;

    _ = c.EVP_PKEY_keygen(context, &pkey);

    // Now do the signature

    const mctx = c.EVP_MD_CTX_new();
    defer c.EVP_MD_CTX_free(mctx);

    // Init signing
    _ = c.EVP_DigestSignInit(mctx, null, null, null, pkey.?);

    // First call: get required signature length
    var sig_len: usize = 0;
    _ = c.EVP_DigestSign(mctx, null, &sig_len, msg.ptr, msg.len);

    const sig = try allocator.alloc(u8, sig_len);
    defer allocator.free(sig);

    // Second call: write signature
    _ = c.EVP_DigestSign(mctx, sig.ptr, &sig_len, msg.ptr, msg.len);

    // Verify signature
    const verify_ctx = c.EVP_MD_CTX_new();
    _ = c.EVP_DigestVerifyInit(verify_ctx, null, null, null, pkey.?);
    defer c.EVP_MD_CTX_free(verify_ctx);
    const v = c.EVP_DigestVerify(verify_ctx, sig.ptr, sig.len, msg.ptr, msg.len);

    // Get keys
    const priv_hex = try getBnOct(allocator, pkey.?, c.OSSL_PKEY_PARAM_PRIV_KEY);
    defer allocator.free(priv_hex);
    const pub_hex = try getBnOct(allocator, pkey.?, c.OSSL_PKEY_PARAM_PUB_KEY);
    defer allocator.free(pub_hex);

    try stdout.print("Curve: Ed25519\n", .{});
    try stdout.print("Message: {s}\n\n", .{msg});

    //  try stdout.print("{s}= 0x{x}\n\n", .{ c.OSSL_PKEY_PARAM_EC_GENERATOR, g_hex });

    try stdout.print("=== Generate priv and pub key === \n\n", .{});

    try stdout.print("{s}= 0x{x}\n\n", .{ c.OSSL_PKEY_PARAM_PRIV_KEY, priv_hex });
    try stdout.print("{s}= 0x{x}\n\n", .{ c.OSSL_PKEY_PARAM_PUB_KEY, pub_hex });

    try stdout.print("Signature: {x} Length: {d} bytes \n\n", .{ sig, sig_len });

    if (v == 1) {
        try stdout.print("Signature has been verified\n\n", .{});
    }
    try stdout.flush();
}
