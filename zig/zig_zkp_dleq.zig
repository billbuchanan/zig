const std = @import("std");
const crypto = @import("std").crypto;

pub fn main() !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    // create a seed for key pair generation

    var secret: []const u8 = undefined;
    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    // Check if there are any arguments
    if (args.len > 1) {
        secret = args[1];
    }

    var x: [crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    crypto.hash.sha2.Sha256.hash(secret, &x, .{});
    var rand: [crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    crypto.hash.sha2.Sha256.hash(secret, &rand, .{});

    const G = crypto.ecc.Secp256k1.random();
    const H = crypto.ecc.Secp256k1.random();

    const xG = try crypto.ecc.Secp256k1.mul(G, x, std.builtin.Endian.big);
    const xH = try crypto.ecc.Secp256k1.mul(H, x, std.builtin.Endian.big);

    // Random value v, and compute [v]G
    var k: [32]u8 = undefined;
    crypto.random.bytes(&k);

    const kG = try crypto.ecc.Secp256k1.mul(G, k, std.builtin.Endian.big);
    const kH = try crypto.ecc.Secp256k1.mul(H, k, std.builtin.Endian.big);

    // Compute c=H(G || [x]G || [v]G)
    var c: [crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    var hasher = crypto.hash.sha2.Sha256.init(.{});
    hasher.update(G.toCompressedSec1()[0..32]);
    hasher.update(xG.toCompressedSec1()[0..32]);
    hasher.update(H.toCompressedSec1()[0..32]);
    hasher.update(xH.toCompressedSec1()[0..32]);
    hasher.update(kG.toCompressedSec1()[0..32]);
    hasher.update(kH.toCompressedSec1()[0..32]);
    hasher.final(&c);

    //  s= v - c.x
    const cx = try crypto.ecc.Secp256k1.scalar.mul(c, x, std.builtin.Endian.big);
    const s = try crypto.ecc.Secp256k1.scalar.sub(k, cx, std.builtin.Endian.big);

    // Peggy sends s and c
    // Victor now computes:
    const sG = try crypto.ecc.Secp256k1.mul(G, s, std.builtin.Endian.big);
    const cY = try crypto.ecc.Secp256k1.mul(xG, c, std.builtin.Endian.big);
    const A = crypto.ecc.Secp256k1.add(sG, cY);

    const sH = try crypto.ecc.Secp256k1.mul(H, s, std.builtin.Endian.big);
    const cxH = try crypto.ecc.Secp256k1.mul(xH, c, std.builtin.Endian.big);
    const B = crypto.ecc.Secp256k1.add(sH, cxH);

    var c1: [crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    hasher = crypto.hash.sha2.Sha256.init(.{});
    hasher.update(G.toCompressedSec1()[0..32]);
    hasher.update(xG.toCompressedSec1()[0..32]);
    hasher.update(H.toCompressedSec1()[0..32]);
    hasher.update(xH.toCompressedSec1()[0..32]);
    hasher.update(A.toCompressedSec1()[0..32]);
    hasher.update(B.toCompressedSec1()[0..32]);
    hasher.final(&c1);

    // if c1 == c, it is proven!

    try stdout.print("Discrete Log Equivalence ZKP with secp256k1\n", .{});
    try stdout.print("\nSecret (x) = {s}\n", .{secret});
    try stdout.print("\nH(x) = {x}\n", .{x});
    try stdout.print("\ns = {x}\n", .{s});
    try stdout.print("\nA = {x}\n", .{A.toCompressedSec1()});
    try stdout.print("\nB = {x}\n", .{B.toCompressedSec1()});
    try stdout.print("\nc = H(G || xG || H || xH || A || B) = {x}\n", .{c});
    try stdout.print("\nc' = H(G || xG || H || xH || A' || B') = {x}\n", .{c1});

    if (std.mem.eql(u8, c[0..32], c1[0..32])) {
        try stdout.print("\nZKP has been proven (c==c1)!\n", .{});
    } else {
        try stdout.print("\nZKP has NOT been proven (c!=c1)!\n", .{});
    }
    try stdout.flush();
}
