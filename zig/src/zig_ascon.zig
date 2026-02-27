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
    var context: []u8 = undefined;
    var len: u32 = 32;

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
        len = try std.fmt.parseInt(u32, args[3], 10);
    }

    var Ascon256: [crypto.ascon.AsconHash256.digest_length]u8 = undefined;

    const Ascon128 = try allocator.alloc(u8, len);
    defer allocator.free(Ascon128);

    const AsconCxof128 = try allocator.alloc(u8, len);
    defer allocator.free(AsconCxof128);

    crypto.ascon.AsconHash256.hash(data, &Ascon256, .{});
    crypto.ascon.AsconXof128.hash(data, Ascon128, .{});
    crypto.ascon.AsconCxof128.hash(data, AsconCxof128, .{ .custom = context });

    try stdout.print("Ascon Hashing: {s}\n", .{data});

    try stdout.print("\nAscon-256: {x}\n", .{Ascon256});
    try stdout.print("\nAscon-XOF-128: {x}\n", .{Ascon128});
    try stdout.print("\nCustom string: {s}\n", .{context});
    try stdout.print("\nAscon-Cxof128: {x}\n", .{AsconCxof128});
    try stdout.flush();
}
