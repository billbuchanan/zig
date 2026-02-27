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

pub fn main() !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    const context = c.EVP_PKEY_CTX_new_from_name(null, "EC", null);
    try stdout.print("\nHello 0\n", .{});
    try stdout.flush();

    _ = c.EVP_PKEY_keygen_init(context);

    var params: [2]c.OSSL_PARAM = undefined;
    const curve_name = "secp256k1";
    params[0] = c.OSSL_PARAM_construct_utf8_string(c.OSSL_PKEY_PARAM_GROUP_NAME, @ptrCast(@constCast(curve_name)), curve_name.len);
    params[1] = c.OSSL_PARAM_construct_end();


    var pkey: ?*c.EVP_PKEY = null;

    _ = c.EVP_PKEY_CTX_set_params(context, &params[0]);


    _ = c.EVP_PKEY_generate(context, &pkey);

    const p_hex = getBnHex(pkey.?, c.OSSL_PKEY_PARAM_EC_P);
    const p_int = getBnDec(pkey.?, c.OSSL_PKEY_PARAM_EC_P);

    try stdout.print("\n{s}: {s}, {s}\n", .{ c.OSSL_PKEY_PARAM_EC_P, p_hex, p_int });

    try stdout.flush();
}
