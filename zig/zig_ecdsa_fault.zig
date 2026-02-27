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

    var r = signature.r;
    const s = signature.s;

    // Now generate a fault
    var k: [32]u8 = undefined;
    crypto.random.bytes(&k);
    var priv1: [32]u8 = undefined;
    crypto.random.bytes(&priv1);

    var h: [crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    var hasher = crypto.hash.sha2.Sha256.init(.{});
    hasher.update(message);
    hasher.final(&h);

    r[0] = r[0] + 1;
    const sf = k.invert().mul(h.add(priv1.mul(r)));

    //sf=(libnum.invmod(k,order)*(h+priv1*rf)) % order
    const valinv = sf.mul(r).sub(s.mul(r)).invert();
    k = h.mul(s.sub(sf)).mul(valinv);
    const dx = h.mul(s.sub(sf)).mul(valinv);

    // k = h*(s-sf) * libnum.invmod(sf*r-s*rf,order)

    // valinv = libnum.invmod( (sf*r-s*rf),order)

    // dx =(h*(s-sf)* valinv) % order

    // Verify with the public key

    try stdout.print("\nKey pair (secret): {x}\n", .{key_pair.secret_key.bytes});
    try stdout.print("\nKey pair (public) - compress: {x}\n", .{key_pair.public_key.toCompressedSec1()});
    try stdout.print("\nKey pair (public) - Non-compress: {x}\n", .{key_pair.public_key.toUncompressedSec1()});

    try stdout.print("\nECDSA P256 signature (r): {x}\n", .{signature.r});
    try stdout.print("\nECDSA P256 signature (s): {x}\n", .{signature.s});

    try stdout.print("\nECDSA P256 private key: {x}\n", .{key_pair.secret_key.bytes});
    try stdout.print("\nECDSA P256 recovered: {x}\n", .{dx});

    try stdout.flush();
}
