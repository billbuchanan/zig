const std = @import("std");
const crypto = @import("std").crypto;
const Ed25519 = crypto.sign.Ed25519;

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
    const key_pair = Ed25519.KeyPair.generate();

    const der_private = try crypto.codecs.asn1.der.encode(std.heap.page_allocator, key_pair);
    //   const der_public = try crypto.codecs.asn1.der.encode(std.heap.page_allocator, key_pair.public_key);

    // Signing
    //   const signature = try key_pair.sign(message, null);

    //   const der_signature = try crypto.encoding.der.encode(signature);

    try stdout.print("\nKey pair (secret): {x}\n", .{key_pair.secret_key.bytes});
    try stdout.print(" DER (private key): {x}\n", .{der_private});
    try stdout.print("\nKey pair (public): {x}\n", .{key_pair.public_key.bytes});
    //   try stdout.print("  DER (public key): {x}\n", .{der_public});
    //   try stdout.print("\nEd25519 signature (r): {x}\n", .{signature.r});
    //   try stdout.print("\nEd25519 signature (s): {x}\n", .{signature.s});
    //   try stdout.print("\n DER Ed25519 signature: {x}\n", .{der_signature});

    try stdout.flush();
}
