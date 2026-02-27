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

    const der_hex = args[1];
    var der = try allocator.alloc(u8, der_hex.len / 2);
    defer allocator.free(der);

    der = try std.fmt.hexToBytes(der, der_hex);

    // Create a BIO that writes to stdout (C FILE*)
    const bio = c.BIO_new(c.BIO_s_mem());
    defer _ = c.BIO_free(bio);

    //   const indent = 1;
    //  const dump = 1;
    // Parse and dump ASN.1 structure from DER bytes
    // int ASN1_parse_dump(BIO *bio, const unsigned char *buf, long len, int indent, int dump);
    //  const rc = c.ASN1_parse_dump(
    ////      bio,
    //     @ptrCast(der.ptr),
    //     @intCast(der.len),
    //    indent,
    //    dump,
    // );

    var bptr: ?*c.BUF_MEM = null;
    _ = c.BIO_get_mem_ptr(bio, &bptr);
    const data_ptr = bptr.?.data;
    const data_len = @as(usize, @intCast(bptr.?.length));

    try stdout.print("=== Dump {s} === \n\n", .{data_ptr[0..data_len]});

    try stdout.flush();
}
