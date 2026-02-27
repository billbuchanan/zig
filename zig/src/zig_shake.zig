const std = @import("std");
const crypto = std.crypto.hash;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    // Get the command-line arguments

    var data: []u8 = undefined;
    var length: []u8 = undefined;
    var context: []u8 = undefined;

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    // Check if there are any arguments
    if (args.len > 1) {
        data = args[1];
    }
    if (args.len > 2) {
        context = args[2];
    }
    if (args.len > 3) {
        length = args[3];
    }

    try stdout.flush();

    const len = try std.fmt.parseInt(usize, length, 10);

    const Shake128 = try allocator.alloc(u8, len);
    defer allocator.free(Shake128);
    const Shake256 = try allocator.alloc(u8, len);
    defer allocator.free(Shake256);
    const CShake128 = try allocator.alloc(u8, len);
    defer allocator.free(CShake128);
    const CShake256 = try allocator.alloc(u8, len);
    defer allocator.free(CShake256);

    crypto.sha3.Shake128.hash(data, Shake128, .{});
    crypto.sha3.Shake256.hash(data, Shake256, .{});
    crypto.sha3.CShake128.hash(data, CShake128, .{ .context = context });
    crypto.sha3.CShake256.hash(data, CShake256, .{ .context = context });

    try stdout.print("Data: {s}\n", .{data});
    try stdout.print("Size: {s} bytes\n", .{length});

    try stdout.print("\nSHAKE128: {x}\n", .{Shake128});
    try stdout.print("SHAKE256: {x}\n", .{Shake256});

    try stdout.print("\nContext string: {s}\n", .{context});
    try stdout.print("cSHAKE128: {x}\n", .{CShake128});
    try stdout.print("cSHAKE256: {x}\n", .{CShake256});

    try stdout.flush();
}
