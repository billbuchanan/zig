const std = @import("std");
const aes = @import("std").crypto.core.aes;

pub fn main() !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    // Get the command-line arguments

    var m: []const u8 = undefined;

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    // Check if there are any arguments
    if (args.len > 1) {
        m = args[1];
    }

    var key: [aes.Aes256.key_bits / 8]u8 = undefined;
    std.crypto.random.bytes(&key);
    var iv: [96]u8 = undefined;
    std.crypto.random.bytes(&iv);

    var stream_block: [16]u8 = undefined;

    var ctx = aes.Aes256.init(key.*);
    ctx.encrypt(&stream_block, &iv);



    try stdout.print("128-bit AES\n", .{});
    try stdout.print("\nMessage: {s}\n", .{m});
    try stdout.print("\nKey:\t{x} \n", .{key});

    try stdout.print("\nCiphertext: {x} \n", .{ciphertext});

    try stdout.print("\nDecrypted: {s} \n", .{m2});
    try stdout.flush();
}
