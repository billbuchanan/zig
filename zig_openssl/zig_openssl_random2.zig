const std = @import("std");

const c = @cImport({
    @cInclude("openssl/bn.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/crypto.h");
});

pub fn main() !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    var val: [*c]u8 = undefined;

    const checks = 64;

    // Check if there are any arguments
    if (args.len > 1) {
        val = args[1];
        if (args[1].len > 664) {
            try stdout.print("Zig interface with OpenSSL. Too many digits (>664). Try with a smaller value.\n\n", .{});
            try stdout.flush();
            return;
        }
    }

    var p: ?*c.BIGNUM = null;
    _ = c.BN_dec2bn(&p, val);

    const isPrime = c.BN_is_prime_ex(p, checks, null, null);

    const hex_cstr = c.BN_bn2hex(p);
    const hex = std.mem.span(hex_cstr);

    const p_dec = c.BN_bn2dec(p);

    const n_bytes = c.BN_num_bytes(p);

    try stdout.print("Zig interface with OpenSSL. Test for prime.\n\n", .{});
    try stdout.print("Value (hex):\t\t{s}\n\n", .{hex});
    try stdout.print("Value (dec):\t\t{s}\n", .{p_dec});
    try stdout.print("\nValue has {d} bytes and {d} bits\t\t\n", .{ n_bytes, n_bytes * 8 });
    if (isPrime == 1) {
        try stdout.print("\nNumber is likely to be prime", .{});
    } else {
        try stdout.print("\nNumber is a composite number (not prime)", .{});
    }
    try stdout.flush();
}
