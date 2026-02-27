const std = @import("std");

const c = @cImport({
    @cInclude("openssl/evp.h");
    @cInclude("openssl/err.h");
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

    var password: [*c]u8 = undefined;
    var salt: [*c]u8 = undefined;

    var iterations: u32 = 1000;
    var dk_len: u32 = 32;
    var salt_len: usize = 0;
    var password_len: usize = 0;

    // Check if there are any arguments
    if (args.len > 1) {
        password = args[1];
        password_len = args[1].len;
    }
    if (args.len > 2) {
        salt = args[2];
        salt_len = args[2].len;
    }
    if (args.len > 3) {
        iterations = try std.fmt.parseInt(u32, args[3], 10);
    }
    if (args.len > 4) {
        dk_len = try std.fmt.parseInt(u32, args[4], 10);
    }

    //  const dk: [*c]u8 = null;
    const dk = try allocator.alloc(u8, dk_len);
    const dk_ptr: [*c]u8 = @ptrCast(dk);
    defer allocator.free(dk);

    // Derive using PBKDF2-HMAC-SHA256
    const md = c.EVP_sha256();

    _ = c.PKCS5_PBKDF2_HMAC(
        password,
        @as(c_int, @intCast(password_len)),
        salt,
        @as(c_int, @intCast(salt_len)),
        @as(c_int, @intCast(iterations)),
        md,
        @as(c_int, @intCast(dk_len)),
        dk_ptr,
    );

    try stdout.print("Zig interface with OpenSSL. PBKDF2-HMAC-SHA256\n\n", .{});
    try stdout.print("Password:\t{s}\n", .{password});
    try stdout.print("Salt:\t\t{s}\n", .{salt});
    try stdout.print("Iterations:\t{d}\n\n", .{iterations});

    try stdout.print("PBKDF2 ({d} bytes):\t{x}\n\n", .{ dk_len, dk });

    try stdout.flush();
}
