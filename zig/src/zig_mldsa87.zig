const std = @import("std");
const crypto = @import("std").crypto;
pub fn main() !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    // Get the command-line arguments

    var msg: []u8 = undefined;

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    // Check if there are any arguments
    if (args.len > 1) {
        msg = args[1];
    }

    try stdout.print("Message: {s}\n", .{msg});

    const kp = crypto.sign.mldsa.MLDSA87.KeyPair.generate();

    const sig = try kp.sign(msg, null);
    const rtn = sig.verify(msg, kp.public_key);

    try stdout.print("\nML-DSA-87\n", .{});

    try stdout.print("\nML-DSA-87 Secret key:\t{x} Length: {d}\n", .{ kp.secret_key.toBytes()[0..256], kp.secret_key.toBytes().len });
    try stdout.print("\nML-DSA-87 Public key:\t{x} Length: {d}\n", .{ kp.public_key.toBytes()[0..256], kp.public_key.toBytes().len });

    try stdout.print("\nML-DSA-87 Signature:\t{x} Length {d}\n", .{ sig.toBytes()[0..256], sig.toBytes().len });

    try stdout.print("\nML-DSA-87 Signature Verified {any}\n", .{rtn});

    try stdout.flush();
}
