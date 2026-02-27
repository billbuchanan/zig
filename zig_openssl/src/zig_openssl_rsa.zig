const std = @import("std");

const c = @cImport({
    @cInclude("openssl/evp.h");
    @cInclude("openssl/params.h");
    @cInclude("openssl/core_names.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/rsa.h");
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

    var msg: []u8 = undefined;
    var key_size: i32 = undefined;

    if (args.len > 1) {
        msg = args[1];
    }
    if (args.len > 2) {
        key_size = try std.fmt.parseInt(i32, args[2], 10);
    }

    const context = c.EVP_PKEY_CTX_new_id(c.EVP_PKEY_RSA, null);

    _ = c.EVP_PKEY_keygen_init(context);
    _ = c.EVP_PKEY_CTX_set_rsa_keygen_bits(context, key_size);

    var pkey: ?*c.EVP_PKEY = null;

    _ = c.EVP_PKEY_keygen(context, &pkey);

    // Now do the signature

    const sign_ctx = c.EVP_MD_CTX_new();
    defer c.EVP_MD_CTX_free(sign_ctx);

    // Init signing
    _ = c.EVP_DigestSignInit(sign_ctx, null, null, null, pkey.?);

    // First call: get required signature length
    var sig_len: usize = 0;
    var pctx: ?*c.EVP_PKEY_CTX = null;
    _ = c.EVP_DigestSignInit(sign_ctx, &pctx, c.EVP_sha256(), null, pkey.?);

    _ = c.EVP_PKEY_CTX_set_rsa_padding(pctx.?, c.RSA_PKCS1_PSS_PADDING);
    _ = c.EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx.?, -1);

    _ = c.EVP_DigestSignFinal(sign_ctx, null, &sig_len);

    const sig = try allocator.alloc(u8, sig_len);
    defer allocator.free(sig);

    _ = c.EVP_DigestSignFinal(sign_ctx, sig.ptr, &sig_len);

    // Get keys
    var n: ?*c.BIGNUM = null;
    var e: ?*c.BIGNUM = null;
    var d: ?*c.BIGNUM = null;
    var p: ?*c.BIGNUM = null;
    var q: ?*c.BIGNUM = null;
    var dP: ?*c.BIGNUM = null;
    var dQ: ?*c.BIGNUM = null;
    var invQ: ?*c.BIGNUM = null;

    _ = c.EVP_PKEY_get_bn_param(pkey.?, c.OSSL_PKEY_PARAM_RSA_N, &n);
    _ = c.EVP_PKEY_get_bn_param(pkey.?, c.OSSL_PKEY_PARAM_RSA_E, &e);
    _ = c.EVP_PKEY_get_bn_param(pkey.?, c.OSSL_PKEY_PARAM_RSA_D, &d);
    _ = c.EVP_PKEY_get_bn_param(pkey.?, c.OSSL_PKEY_PARAM_RSA_FACTOR1, &p);
    _ = c.EVP_PKEY_get_bn_param(pkey.?, c.OSSL_PKEY_PARAM_RSA_FACTOR2, &q);

    _ = c.EVP_PKEY_get_bn_param(pkey.?, c.OSSL_PKEY_PARAM_RSA_EXPONENT1, &dP);
    _ = c.EVP_PKEY_get_bn_param(pkey.?, c.OSSL_PKEY_PARAM_RSA_EXPONENT2, &dQ);
    _ = c.EVP_PKEY_get_bn_param(pkey.?, c.OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &invQ);

    defer c.BN_free(n.?);
    defer c.BN_free(e.?);
    defer c.BN_free(d.?);
    defer c.BN_free(p.?);
    defer c.BN_free(q.?);
    defer c.BN_free(dP.?);
    defer c.BN_free(dQ.?);
    defer c.BN_free(invQ.?);

    try stdout.print("=== RSA-{d} (PSS). Message: {s} === \n\n", .{ key_size, msg });

    try stdout.print("Public key: e={s}, N= {s} \n\n", .{ c.BN_bn2hex(e.?), c.BN_bn2hex(n.?) });
    try stdout.print("Private key: d={s}, N= {s} \n\n", .{ c.BN_bn2hex(d.?), c.BN_bn2hex(n.?) });

    try stdout.print("Signature: {x} Length: {d} bytes \n\n", .{ sig, sig_len });

    try stdout.print("p={s}\nq= {s}\n\n", .{ c.BN_bn2hex(p.?), c.BN_bn2hex(q.?) });

    try stdout.print("dP: {s}, dQ: {s}, invQ: {s}", .{ c.BN_bn2hex(dP), c.BN_bn2hex(dQ), c.BN_bn2hex(invQ) });

    try stdout.flush();
}
