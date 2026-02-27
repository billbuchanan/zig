const std = @import("std");

const c = @cImport({
    @cInclude("openssl/evp.h");
    @cInclude("openssl/kdf.h");
    @cInclude("openssl/params.h");
    @cInclude("openssl/core_names.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/ec.h");
});

fn getBnHex(pkey: *c.EVP_PKEY, name: [*c]const u8) [*c]u8 {
    var bn: ?*c.BIGNUM = null;
    _ = c.EVP_PKEY_get_bn_param(pkey, name, &bn);
    const str = c.BN_bn2hex(bn.?);
    return (str);
}
fn getBnDec(pkey: *c.EVP_PKEY, name: [*c]const u8) [*c]u8 {
    var bn: ?*c.BIGNUM = null;
    _ = c.EVP_PKEY_get_bn_param(pkey, name, &bn);
    const str = c.BN_bn2dec(bn.?);
    return (str);
}
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

    const context = c.EVP_PKEY_CTX_new_from_name(null, "EC", null);

    _ = c.EVP_PKEY_keygen_init(context);

    var curve_name: []u8 = undefined;
    var msg: []u8 = undefined;

    if (args.len > 1) {
        msg = args[1];
    }
    if (args.len > 2) {
        curve_name = args[2];
    }

    var params: [2]c.OSSL_PARAM = undefined;

    params[0] = c.OSSL_PARAM_construct_utf8_string(c.OSSL_PKEY_PARAM_GROUP_NAME, @ptrCast(@constCast(curve_name)), curve_name.len);
    params[1] = c.OSSL_PARAM_construct_end();

    var pkey: ?*c.EVP_PKEY = null;

    _ = c.EVP_PKEY_CTX_set_params(context, &params);

    _ = c.EVP_PKEY_generate(context, &pkey);

    const p_hex = getBnHex(pkey.?, c.OSSL_PKEY_PARAM_EC_P);
    const p_int = getBnDec(pkey.?, c.OSSL_PKEY_PARAM_EC_P);
    const a_hex = getBnHex(pkey.?, c.OSSL_PKEY_PARAM_EC_A);
    const a_int = getBnDec(pkey.?, c.OSSL_PKEY_PARAM_EC_A);
    const b_hex = getBnHex(pkey.?, c.OSSL_PKEY_PARAM_EC_B);
    const b_int = getBnDec(pkey.?, c.OSSL_PKEY_PARAM_EC_B);
    const order_hex = getBnHex(pkey.?, c.OSSL_PKEY_PARAM_EC_ORDER);
    const order_int = getBnDec(pkey.?, c.OSSL_PKEY_PARAM_EC_ORDER);
    const priv_hex = getBnHex(pkey.?, c.OSSL_PKEY_PARAM_PRIV_KEY);
    const g_hex = try getBnOct(allocator, pkey.?, c.OSSL_PKEY_PARAM_EC_GENERATOR);
    defer allocator.free(g_hex);
    const pub_hex = try getBnOct(allocator, pkey.?, c.OSSL_PKEY_PARAM_PUB_KEY);
    defer allocator.free(pub_hex);

    // Now do the signature

    const mctx = c.EVP_MD_CTX_new();
    defer c.EVP_MD_CTX_free(mctx);

    // Init signing (SHA-256)
    _ = c.EVP_DigestSignInit(mctx, null, c.EVP_sha256(), null, pkey.?);

    _ = c.EVP_DigestSignUpdate(mctx, msg.ptr, msg.len);

    // First call: get required signature length
    var sig_len: usize = 0;
    _ = c.EVP_DigestSignFinal(mctx, null, &sig_len);

    const sig = try allocator.alloc(u8, sig_len);
    defer allocator.free(sig);

    // Second call: write signature
    _ = c.EVP_DigestSignFinal(mctx, sig.ptr, &sig_len);

    try stdout.print("Curve: {s}\n", .{curve_name});
    try stdout.print("Message: {s}\n\n", .{msg});

    try stdout.print("{s}= 0x{s} ({s})\n\n", .{ c.OSSL_PKEY_PARAM_EC_P, p_hex, p_int });
    try stdout.print("{s}= 0x{s} ({s})\n\n", .{ c.OSSL_PKEY_PARAM_EC_A, a_hex, a_int });
    try stdout.print("{s}= 0x{s} ({s})\n\n", .{ c.OSSL_PKEY_PARAM_EC_B, b_hex, b_int });
    try stdout.print("{s}= 0x{s} ({s})\n\n", .{ c.OSSL_PKEY_PARAM_EC_ORDER, order_hex, order_int });

    try stdout.print("=== Generate priv and pub key === \n\n", .{});

    try stdout.print("{s}= 0x{x}\n\n", .{ c.OSSL_PKEY_PARAM_EC_GENERATOR, g_hex });
    try stdout.print("{s}= 0x{s}\n\n", .{ c.OSSL_PKEY_PARAM_PRIV_KEY, priv_hex });
    try stdout.print("{s}= 0x{x}\n\n", .{ c.OSSL_PKEY_PARAM_PUB_KEY, pub_hex });

    try stdout.print("Signature: {x} Length: {d} bytes \n\n", .{ sig, sig_len });

    try stdout.flush();
}