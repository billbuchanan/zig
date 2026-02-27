const std = @import("std");
const crypto = @import("std").crypto;
const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;

pub fn main() !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    // Get the command-line arguments

    var ikm: []u8 = undefined;
    var salt: []u8 = undefined;
    var info: []u8 = undefined;

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    // Check if there are any arguments
    if (args.len > 1) ikm = args[1];
    if (args.len > 2) salt = args[2];
    if (args.len > 3) info = args[3];

    try stdout.print("IKM:\t{s}\n", .{ikm});
    try stdout.print("Salt:\t{s}\n", .{salt});
    try stdout.print("Info:\t{s}\n", .{info});

    // 1. Determine the PRK
    const prk = HkdfSha256.extract(salt, ikm);

    // 2. Expand PRK to get 32-byte key
    var key_32byte: [32]u8 = undefined;
    HkdfSha256.expand(&key_32byte, info, prk);

    // 3. Expand PRK to get 64-byte key
    var key_64byte: [64]u8 = undefined;
    HkdfSha256.expand(&key_64byte, info, prk);

    try stdout.print("\nHKDF\n", .{});

    try stdout.print("\nPRK:\t{x}\n", .{prk});

    try stdout.print("\n32-byte key:\t{x}\n", .{key_32byte});

    try stdout.print("\n64-byte key:\t{x}\n", .{key_64byte});

    try stdout.flush();
}
