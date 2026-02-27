const std = @import("std");
const hash = @import("std").crypto.hash;

pub fn main() !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    // Get the command-line arguments

    var m1: []const u8 = undefined;
    var m2: []const u8 = undefined;

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    // Check if there are any arguments
    if (args.len > 1) {
        m1 = args[1];
    }
    if (args.len > 2) {
        m2 = args[2];
    }

    var tuple128 = hash.sha3.TupleHash128.init();
    var tuple256 = hash.sha3.TupleHash256.init();

    tuple128.update(m1);
    tuple128.update(m2);

    tuple256.update(m1);
    tuple256.update(m2);

    var out1: [32]u8 = undefined;
    var out2: [64]u8 = undefined;
    tuple128.final(&out1);
    tuple256.final(&out2);

    try stdout.print("\nMessage 1: {s} \n", .{m1});
    try stdout.print("Message 2: {s} \n", .{m2});
    try stdout.print("\nTuple128: {x} \n", .{out1});
    try stdout.print("\nTuple256: {x} \n", .{out2});
    try stdout.flush();
}
