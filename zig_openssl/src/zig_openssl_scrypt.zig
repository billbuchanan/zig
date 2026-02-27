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

    var N: u64 = 16384;
    var r: u64 = 8;
    var p: u64 = 1;
    const maxmem: u64 = (32 * 1024 * 1024);

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
        N = try std.fmt.parseInt(u32, args[3], 10);
    }
    if (args.len > 4) {
        r = try std.fmt.parseInt(u32, args[4], 10);
    }
    if (args.len > 5) {
        p = try std.fmt.parseInt(u32, args[5], 10);
    }
    if (args.len > 6) {
        dk_len = try std.fmt.parseInt(u32, args[6], 10);
    }

    //  const dk: [*c]u8 = null;
    const dk = try allocator.alloc(u8, dk_len);
    const dk_ptr: [*c]u8 = @ptrCast(dk);
    defer allocator.free(dk);

    _ = c.EVP_PBE_scrypt(password, password_len, salt, salt_len, N, r, p, maxmem, dk_ptr, (dk_len));

    try stdout.print("Zig interface with OpenSSL. scrypt\n\n", .{});
    try stdout.print("Password:\t{s}\n", .{password});
    try stdout.print("Salt:\t\t{s}\n\n", .{salt});
    try stdout.print("N:\t{d}\n", .{N});
    try stdout.print("r:\t{d}\n", .{r});
    try stdout.print("p:\t{d}\n", .{p});
    try stdout.print("memax:\t{d}\n\n", .{maxmem});
    try stdout.print("\nscrypt ({d} bytes):\t{x}\n\n", .{ dk_len, dk });

    try stdout.flush();
}
