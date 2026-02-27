const std = @import("std");
const crypto = std.crypto.auth;

pub fn main() !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    // Create keys for KMac
    var key256: [32]u8 = undefined;
    var key128: [crypto.aegis.Aegis128LMac.key_length]u8 = undefined;

    // Fill 'key' with a secure random key
    std.crypto.random.bytes(&key256);
    std.crypto.random.bytes(&key128);

    // Get the command-line arguments

    var data: []u8 = undefined;

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    // Check if there are any arguments
    if (args.len > 1) {
        data = args[1];
    }

    var Aegis128LMac: [crypto.aegis.Aegis128LMac.mac_length]u8 = undefined;
    var Aegis128X2Mac: [crypto.aegis.Aegis128LMac.mac_length]u8 = undefined;
    var Aegis128X4Mac: [crypto.aegis.Aegis128LMac.mac_length]u8 = undefined;

    var Aegis256Mac: [crypto.aegis.Aegis256Mac.mac_length]u8 = undefined;
    var Aegis256X2Mac: [crypto.aegis.Aegis128LMac.mac_length]u8 = undefined;
    var Aegis256X4Mac: [crypto.aegis.Aegis128LMac.mac_length]u8 = undefined;

    std.crypto.auth.aegis.Aegis128LMac.create(&Aegis128LMac, data, &key128);
    std.crypto.auth.aegis.Aegis128X2Mac.create(&Aegis128X2Mac, data, &key128);
    std.crypto.auth.aegis.Aegis128X4Mac.create(&Aegis128X4Mac, data, &key128);

    std.crypto.auth.aegis.Aegis256Mac.create(&Aegis256Mac, data, &key256);
    std.crypto.auth.aegis.Aegis256X2Mac.create(&Aegis256X2Mac, data, &key256);
    std.crypto.auth.aegis.Aegis256X4Mac.create(&Aegis256X4Mac, data, &key256);

    try stdout.print("Aegis:\t\t{s}\n", .{data});
    try stdout.print(" Key (128-bit):\t{x}\n", .{key128});
    try stdout.print(" Key (256-bit):\t{x}\n", .{key256});

    try stdout.print("\nAegis128LMac:\t{x}\n", .{Aegis128LMac});
    try stdout.print("\nAegis128X2Mac:\t{x}\n", .{Aegis128X2Mac});
    try stdout.print("\nAegis128X4Mac:\t{x}\n", .{Aegis128X4Mac});

    try stdout.print("\nAegis256Mac:\t{x}\n", .{Aegis256Mac});
    try stdout.print("\nAegis256X2Mac:\t{x}\n", .{Aegis256X2Mac});
    try stdout.print("\nAegis256X4Mac:\t{x}\n", .{Aegis256X4Mac});
    try stdout.flush();
}
