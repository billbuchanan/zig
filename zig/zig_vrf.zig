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

    var k: [32]u8 = undefined;
    crypto.random.bytes(&k);

    var r: [32]u8 = undefined;
    crypto.random.bytes(&r);

    const G = crypto.ecc.Secp256k1.basePoint;
    //  const H = crypto.ecc.Secp256k1.random();

    const Q = try crypto.ecc.Secp256k1.basePoint.mul(k, std.builtin.Endian.big);

    var m: [crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    crypto.hash.sha2.Sha256.hash(secret, &m, .{});

    const H = try crypto.ecc.Secp256k1.basePoint.mul(m, std.builtin.Endian.big);

    const VRF = try crypto.ecc.Secp256k1.mul(H, k, std.builtin.Endian.big);
    const rG = try crypto.ecc.Secp256k1.mul(G, r, std.builtin.Endian.big);
    const rH = try crypto.ecc.Secp256k1.mul(H, r, std.builtin.Endian.big);

    // Compute c=H(G || H || [k]G || VRF || [r]G || [r[H]])
    var s: [crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    var hasher = crypto.hash.sha2.Sha256.init(.{});
    hasher.update(G.toCompressedSec1()[0..32]);
    hasher.update(H.toCompressedSec1()[0..32]);
    hasher.update(Q.toCompressedSec1()[0..32]);
    hasher.update(VRF.toCompressedSec1()[0..32]);
    hasher.update(rG.toCompressedSec1()[0..32]);
    hasher.update(rH.toCompressedSec1()[0..32]);
    hasher.final(&s);

    //  s= r - s.k
    const sk = try crypto.ecc.Secp256k1.scalar.mul(s, k, std.builtin.Endian.big);
    const t = try crypto.ecc.Secp256k1.scalar.sub(r, sk, std.builtin.Endian.big);

    // Peggy sends s and c
    // Victor now computes:

    const tG = try crypto.ecc.Secp256k1.mul(G, t, std.builtin.Endian.big);
    const skG = try crypto.ecc.Secp256k1.mul(Q, s, std.builtin.Endian.big);
    const B1 = crypto.ecc.Secp256k1.add(tG, skG);

    const tH = try crypto.ecc.Secp256k1.mul(H, t, std.builtin.Endian.big);
    const sVRF = try crypto.ecc.Secp256k1.mul(VRF, s, std.builtin.Endian.big);
    const B2 = crypto.ecc.Secp256k1.add(tH, sVRF);

    var c: [crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    hasher = crypto.hash.sha2.Sha256.init(.{});
    hasher.update(G.toCompressedSec1()[0..32]);
    hasher.update(H.toCompressedSec1()[0..32]);
    hasher.update(Q.toCompressedSec1()[0..32]);
    hasher.update(VRF.toCompressedSec1()[0..32]);
    hasher.update(B1.toCompressedSec1()[0..32]);
    hasher.update(B2.toCompressedSec1()[0..32]);
    hasher.final(&c);

    // if c1 == c, it is proven!

    try stdout.print("Discrete Log Equivalence ZKP with secp256k1\n", .{});

    try stdout.print("\nc = H(G || xG || H || xH || A || B) = {x}\n", .{s});
    try stdout.print("\nc' = H(G || xG || H || xH || A' || B') = {x}\n", .{c});

    if (std.mem.eql(u8, s[0..32], c[0..32])) {
        try stdout.print("\nZKP has been proven (c==c1)!\n", .{});
    } else {
        try stdout.print("\nZKP has NOT been proven (c!=c1)!\n", .{});
    }
    try stdout.flush();
}
