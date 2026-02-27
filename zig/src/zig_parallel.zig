const std = @import("std");
const crypto = std.crypto.hash;
const Io = std.Io;
pub fn main() !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    // Get the command-line arguments

    var data: []u8 = undefined;

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    // Check if there are any arguments
    if (args.len > 1) {
        data = args[1];
    }

    var KT128: [crypto.sha3.KT128.digest_length]u8 = undefined;
    var KT256: [crypto.sha3.KT256.digest_length]u8 = undefined;

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const arena_allocator = arena.allocator();


    try crypto.sha3.KT128.hashParallel(data, &KT128, .{}, arena_allocator, Threaded);

    try crypto.sha3.KT256.hashParallel(data, &KT256, .{}, arena_allocator, Io.Writer());

    //   try crypto.sha3.KT128.hash(data, &KT128, .{});
    //   try crypto.sha3.KT256.hash(data, &KT256, .{});

    try stdout.print("Hashing: {s}\n", .{data});
    try stdout.print("Kangaroo 12 (128) {x}\n", .{KT128});
    try stdout.print("Kangaroo 12 (256) {x}\n", .{KT256});
    stdout.flush();
}
