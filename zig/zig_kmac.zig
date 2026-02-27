const std = @import("std");
const crypto = std.crypto.hash;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    // Create keys for KMac
    var key256: [32]u8 = undefined;
    var key128: [16]u8 = undefined;

    // Fill 'key' with a secure random key
    std.crypto.random.bytes(&key256);
    std.crypto.random.bytes(&key128);

    // Get the command-line arguments

    var data: []u8 = undefined;
    var length: []u8 = undefined;
    var key: []u8 = undefined;

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    // Check if there are any arguments
    if (args.len > 1) {
        data = args[1];
    }
    if (args.len > 2) {
        key = args[2];
    }

    if (args.len > 3) {
        length = args[3];
    }

    const len = try std.fmt.parseInt(usize, length, 10);

    const KMac128 = try allocator.alloc(u8, len);
    defer allocator.free(KMac128);
    const KMac256 = try allocator.alloc(u8, len);
    defer allocator.free(KMac256);

    crypto.sha3.KMac128.create(KMac128, data, key);
    crypto.sha3.KMac256.create(KMac256, data, key);

    try stdout.print("KMAC:\t\t{s}\n", .{data});
    try stdout.print("\nKey:\t\t{s}\n", .{key});
    try stdout.print("MAC size:\t{d}\n", .{len});

    try stdout.print("\nKMAC128:\t{x}\n", .{KMac128});
    try stdout.print("\nKMAC256:\t{x}\n", .{KMac256});

    try stdout.flush();
}
