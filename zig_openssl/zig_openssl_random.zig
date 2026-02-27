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

    var bits: c_int = 256; // change as desired (e.g., 2048)
    var safe: c_int = 0; // 1 => generate a safe prime (p=2q+1), slower

    // Check if there are any arguments
    if (args.len > 1) {
        bits = try std.fmt.parseInt(i32, args[1], 10);
    }
    if (args.len > 2) {
        safe = try std.fmt.parseInt(i32, args[2], 10);
    }

    const p = c.BN_new();

    _ = c.BN_generate_prime_ex(p, bits, safe, null, null, null);

    const isPrime = c.BN_is_prime_ex(p, bits, null, null);

    const hex_cstr = c.BN_bn2hex(p);
    const hex = std.mem.span(hex_cstr);

    const p_dec = c.BN_bn2dec(p);

    try stdout.print("Zig interface with OpenSSL. Safe: {d}\n\n", .{safe});
    if (safe == 1) try stdout.print("Safe prime\n\n", .{});
    try stdout.print("Random {d}-bit prime (hex):\t\t{s}\n\n", .{ bits, hex });
    try stdout.print("Random {d}-bit prime (dec):\t\t{s}", .{ bits, p_dec });
    if (isPrime == 1) try stdout.print("\nNumber tested as a prime", .{});

    try stdout.flush();
}
