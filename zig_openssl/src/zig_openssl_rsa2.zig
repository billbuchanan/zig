const std = @import("std");

const c = @cImport({
    @cInclude("openssl/evp.h");
    @cInclude("openssl/params.h");
    @cInclude("openssl/core_names.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/rsa.h");
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

    var msg: []u8 = undefined;
    var key_size: i32 = undefined;

    if (args.len > 1) {
        msg = args[1];
    }
    if (args.len > 2) {
        key_size = try std.fmt.parseInt(i32, args[2], 10);
    }

    // Generate 2K RSA key par
    const context = c.EVP_PKEY_CTX_new_id(c.EVP_PKEY_RSA, null);

    _ = c.EVP_PKEY_keygen_init(context);
    _ = c.EVP_PKEY_CTX_set_rsa_keygen_bits(context, key_size);

    var pkey: ?*c.EVP_PKEY = null;

    _ = c.EVP_PKEY_keygen(context, &pkey);
    defer c.EVP_PKEY_free(pkey.?);

    // Now do the encryption

    const enc_ctx = c.EVP_PKEY_CTX_new(pkey.?, null);
    defer c.EVP_PKEY_CTX_free(enc_ctx);

    // Init encryption
    _ = c.EVP_PKEY_encrypt_init(enc_ctx);
    // Do OAEP padding
    _ = c.EVP_PKEY_CTX_set_rsa_padding(enc_ctx, c.RSA_PKCS1_OAEP_PADDING);
    // Do SHA-256 and MGF1 hash
    _ = c.EVP_PKEY_CTX_set_rsa_oaep_md(enc_ctx, c.EVP_sha256());
    _ = c.EVP_PKEY_CTX_set_rsa_mgf1_md(enc_ctx, c.EVP_sha256());

    var ct_len: usize = 0;
    _ = c.EVP_PKEY_encrypt(enc_ctx, null, &ct_len, msg.ptr, msg.len);

    const ct = try allocator.alloc(u8, ct_len);
    defer allocator.free(ct);

    _ = c.EVP_PKEY_encrypt(enc_ctx, ct.ptr, &ct_len, msg.ptr, msg.len);

    // Now decrypt
    const dec_ctx = c.EVP_PKEY_CTX_new(pkey.?, null);
    defer c.EVP_PKEY_CTX_free(dec_ctx);

    _ = c.EVP_PKEY_decrypt_init(dec_ctx);

    _ = c.EVP_PKEY_CTX_set_rsa_padding(dec_ctx, c.RSA_PKCS1_OAEP_PADDING);
    _ = c.EVP_PKEY_CTX_set_rsa_oaep_md(dec_ctx, c.EVP_sha256());
    _ = c.EVP_PKEY_CTX_set_rsa_mgf1_md(dec_ctx, c.EVP_sha256());
    var pt_len: usize = 0;
    _ = c.EVP_PKEY_decrypt(dec_ctx, null, &pt_len, ct.ptr, ct.len);

    const pt = try allocator.alloc(u8, pt_len);
    defer allocator.free(pt);

    _ = c.EVP_PKEY_decrypt(dec_ctx, pt.ptr, &pt_len, ct.ptr, ct.len);

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

    try stdout.print("=== RSA-{d} (OAEP). Message: {s} === \n\n", .{ key_size, msg });

    try stdout.print("Public key: e={s}, N= {s} \n\n", .{ c.BN_bn2hex(e.?), c.BN_bn2hex(n.?) });
    try stdout.print("Private key: d={s}, N= {s} \n\n", .{ c.BN_bn2hex(d.?), c.BN_bn2hex(n.?) });
    try stdout.print("  p={s}\n  q= {s}\n\n", .{ c.BN_bn2hex(p.?), c.BN_bn2hex(q.?) });

    try stdout.print("Ciphertext: {x} Length: {d} bytes \n\n", .{ ct[0..ct_len], ct_len });
    try stdout.print("Plaintext: {s} Length: {d} bytes \n\n", .{ pt[0..pt_len], pt_len });

    try stdout.print("dP: {s}, dQ: {s}, invQ: {s}", .{ c.BN_bn2hex(dP), c.BN_bn2hex(dQ), c.BN_bn2hex(invQ) });

    try stdout.flush();
}
