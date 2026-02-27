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

    const G = crypto.ecc.Secp256k1.basePoint;
    // Peggy's private key
    var m: [crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    crypto.hash.sha2.Sha256.hash(secret, &m, .{});

    const H = try crypto.ecc.Secp256k1.basePoint.mul(m, std.builtin.Endian.big);

    // Peggy's private key
    var k: [32]u8 = undefined;
    crypto.random.bytes(&k);

    const kG = try crypto.ecc.Secp256k1.mul(G, k, std.builtin.Endian.big);

    // VRF
    const kH = try crypto.ecc.Secp256k1.mul(H, k, std.builtin.Endian.big);

    // Peggy select random value (r)
    var r: [32]u8 = undefined;
    crypto.random.bytes(&r);

    const rH = try crypto.ecc.Secp256k1.mul(H, r, std.builtin.Endian.big);
    const rG = try crypto.ecc.Secp256k1.mul(G, r, std.builtin.Endian.big);

    // Compute c=H(G || H || [k]G || [k]H ||  [r]G || [r]H)
    var s: [crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    var hasher = crypto.hash.sha2.Sha256.init(.{});
    hasher.update(G.toCompressedSec1()[0..32]);
    hasher.update(H.toCompressedSec1()[0..32]);
    hasher.update(kG.toCompressedSec1()[0..32]);
    hasher.update(kH.toCompressedSec1()[0..32]);
    hasher.update(rG.toCompressedSec1()[0..32]);
    hasher.update(rH.toCompressedSec1()[0..32]);
    hasher.final(&s);

    // t = r - s.k
    const sk = try crypto.ecc.Secp256k1.scalar.mul(s, k, std.builtin.Endian.big);
    const t = try crypto.ecc.Secp256k1.scalar.sub(r, sk, std.builtin.Endian.big);

    // Peggy sends s and t

    // Victor now computes:
    // [t]G + [s]([k]G)
    const tG = try crypto.ecc.Secp256k1.mul(G, t, std.builtin.Endian.big);
    const s_kG = try crypto.ecc.Secp256k1.mul(kG, s, std.builtin.Endian.big);
    const A = crypto.ecc.Secp256k1.add(tG, s_kG);

    // [t]H + [s]([k]H)
    const tH = try crypto.ecc.Secp256k1.mul(H, t, std.builtin.Endian.big);
    const s_kH = try crypto.ecc.Secp256k1.mul(kH, s, std.builtin.Endian.big);
    const B = crypto.ecc.Secp256k1.add(tH, s_kH);

    var s1: [crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    hasher = crypto.hash.sha2.Sha256.init(.{});
    hasher.update(G.toCompressedSec1()[0..32]);
    hasher.update(H.toCompressedSec1()[0..32]);
    hasher.update(kG.toCompressedSec1()[0..32]);
    hasher.update(kH.toCompressedSec1()[0..32]);
    hasher.update(A.toCompressedSec1()[0..32]);
    hasher.update(B.toCompressedSec1()[0..32]);
    hasher.final(&s1);

    // if s1 == s, it is proven!

    try stdout.print("Verifiable Random Function (VRF) with secp256k1\n", .{});
    try stdout.print("\nSecret (x) = {s}\n", .{secret});
    try stdout.print("\nH = {x}\n", .{H.toCompressedSec1()});
    try stdout.print("\ns = {x}\n", .{s});
    try stdout.print("\nt = {x}\n", .{t});
    try stdout.print("\n[r]G = {x}\n", .{rG.toCompressedSec1()});
    try stdout.print("\n[r]H = {x}\n", .{rH.toCompressedSec1()});
    try stdout.print("\ns = H(G || H || [k]G || [k]H || [r]G || [r]H ) = {x}\n", .{s});
    try stdout.print("\ns' = H(G || H || [k]G || [k]H || [t]G + [s]([k]G)) || [t]H + [s]([k]H)) = {x}\n", .{s1});

    if (std.mem.eql(u8, s[0..32], s1[0..32])) {
        try stdout.print("\nVRF has been proven (s==s')!\n", .{});
    } else {
        try stdout.print("\nVRF has NOT been proven (s!=s')!\n", .{});
    }
    try stdout.flush();
}
