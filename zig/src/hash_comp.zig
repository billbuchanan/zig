const std = @import("std");
const crypto = std.crypto.hash;

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

    try stdout.print("Hashing: {s}\n", .{data});
    try stdout.flush();

    var Md5oMd5: [16]u8 = undefined;
    var Sha1oSha1: [20]u8 = undefined;

    var Sha256oSha256: [32]u8 = undefined;
    var Sha384oSha384: [48]u8 = undefined;
    var Sha512oSha512: [64]u8 = undefined;

    crypto.composition.Sha256oSha256.hash(data, &Sha256oSha256, .{});
    crypto.composition.Sha384oSha384.hash(data, &Sha384oSha384, .{});
    crypto.composition.Sha512oSha512.hash(data, &Sha512oSha512, .{});

    crypto.composition.Md5oMd5.hash(data, &Md5oMd5, .{});
    crypto.composition.Sha1oSha1.hash(data, &Sha1oSha1, .{});

    try stdout.print("Sha256oSha256 {x}\n", .{Sha256oSha256});
    try stdout.print("Sha384oSha384 {x}\n", .{Sha384oSha384});
    try stdout.print("Sha512oSha512 {x}\n", .{Sha512oSha512});

    try stdout.print("\nMd5oMd5 {x}\n", .{Md5oMd5});
    try stdout.print("Sha1oSha1 {x}\n", .{Sha1oSha1});
    try stdout.flush();
}
