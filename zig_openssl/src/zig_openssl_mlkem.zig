const std = @import("std");

const c = @cImport({
    @cInclude("openssl/evp.h");
    @cInclude("openssl/params.h");
    @cInclude("openssl/core_names.h");
    @cInclude("openssl/err.h");
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

    var ml_name: [*c]u8 = undefined; // eg ML-KEM-768

    if (args.len > 1) {
        ml_name = args[1];
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

    try stdout.print("=== {s} ===\n\n", .{ml_name});

    try stdout.print("Priv (first 500 bytes)= 0x{x} Length: {d} bytes\n\n", .{ priv[0..500], priv.len });
    try stdout.print("Pub (first 500 bytes)= 0x{x} Length: {d} bytes\n\n", .{ public[0..500], public.len });
    try stdout.flush();
}
