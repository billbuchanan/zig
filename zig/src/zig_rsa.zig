const std = @import("std");

const RS = @import("rsa.zig");

pub fn main() !void {
    var message: []const u8 = undefined;

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    // Check if there are any arguments
    if (args.len > 1) {
        message = args[1];
    }

    const RSA_256 = u256;
    //   const RSA_512 = u512; // use for RSA-1024
    //   const RSA_1024 = u1024; // use for RSA-2048

    const RSA_Method = RS.RSA(RSA_256);

    const p = RS.Numeric.randomPrime(RSA_256, .{});
    const q = RS.Numeric.randomPrime(RSA_256, .{});

    const rsa = RSA_Method.init(p, q);

    const encrypted = try rsa.encrypt(message, allocator);
    const decrypted = try rsa.decrypt(encrypted, allocator);

    try stdout.writeAll("RSA-512 Encryption\n");
    try stdout.print("Message: {s}\n", .{message});
    try stdout.print("\np={}\nq={}\n", .{ p, q });
    try stdout.print("\nEncrypted: {x}\n", .{encrypted});
    try stdout.print("\nDecrypted: {s}\n", .{decrypted[0..message.len]});

    try stdout.flush();
}
