const std = @import("std");

const c = @cImport({
    @cInclude("openssl/asn1.h");
    @cInclude("openssl/bio.h");
    @cInclude("openssl/buffer.h"); // BUF_MEM
    @cInclude("openssl/err.h");
});

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const der_hex = args[1];

    const indent: c_int = 0;

    const dump = 0;

    var der = try allocator.alloc(u8, der_hex.len / 2);
    defer allocator.free(der);

    der = try std.fmt.hexToBytes(der, der_hex);

    // ---- Use a memory BIO (avoids c.stdout macro on Windows) ----
    const bio = c.BIO_new(c.BIO_s_mem());
    defer _ = c.BIO_free(bio);

    _ = c.ASN1_parse_dump(
        bio,
        @as([*c]const u8, @ptrCast(der.ptr)),
        @as(c_long, @intCast(der.len)),
        indent,
        dump,
    );

    // Extract memory BIO contents
    var bptr: ?*c.BUF_MEM = null;
    _ = c.BIO_get_mem_ptr(bio, &bptr);

    const data_ptr = bptr.?.data;
    const data_len = @as(usize, @intCast(bptr.?.length));

    try stdout.print("=== DER {s} === \n\n", .{der_hex});

    if (data_ptr != null and data_len > 0) {
        const slice = @as([*]const u8, @ptrCast(data_ptr))[0..data_len];
        try stdout.writeAll(slice);
    }

    try stdout.flush();
}
