const std = @import("std");
const crypto = @import("std").crypto;
const ECDSA = crypto.sign.ecdsa;

pub fn main() !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    // Get the command-line arguments

    var message: []u8 = undefined;

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    // Check if there are any arguments
    if (args.len > 1) {
        message = args[1];
    }

    try stdout.print("Message: {s}\n", .{message});

    // Key Generation
    const key_pair = ECDSA.EcdsaP256Sha256.KeyPair.generate();
    const public_key = key_pair.public_key; // Share this public key

    // Signing

    const signature = try key_pair.sign(message, null); // Deterministic signature

    // Verify with the public key

    try stdout.print("\nKey pair (secret): {x}\n", .{key_pair.secret_key.bytes});
    try stdout.print("\nKey pair (public) - compress: {x}\n", .{key_pair.public_key.toCompressedSec1()});
    try stdout.print("\nKey pair (public) - Non-compress: {x}\n", .{key_pair.public_key.toUncompressedSec1()});

    try stdout.print("\nECDSA P256 signature (r): {x}\n", .{signature.r});
    try stdout.print("\nECDSA P256 signature (s): {x}\n", .{signature.s});

    var rtn = signature.verify(message, public_key);
    try stdout.print("\nSignature verification. Rtn: {!}\n", .{rtn});

    const incorrect_message = "Wrong message!";
    rtn = signature.verify(incorrect_message, public_key);
    try stdout.print("\nSignature verification (with wrong message). Rtn: {!}\n", .{rtn});

    try stdout.flush();
}
