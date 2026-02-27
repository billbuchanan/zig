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

    const G = crypto.ecc.Ristretto255.basePoint;
    const H = try crypto.ecc.Ristretto255.basePoint.mul(rand);

    const xG = try crypto.ecc.Ristretto255.mul(G, x);
    const xH = try crypto.ecc.Ristretto255.mul(H, x);

    // Random value v, and compute [v]G
    var k: [32]u8 = undefined;
    crypto.random.bytes(&k);

    const kG = try crypto.ecc.Ristretto255.mul(G, k);
    const kH = try crypto.ecc.Ristretto255.mul(H, k);

    // Compute c=H(G || [x]G || [v]G)
    var c: [crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    var hasher = crypto.hash.sha2.Sha256.init(.{});
    hasher.update(G.toBytes()[0..32]);
    hasher.update(xG.toBytes()[0..32]);
    hasher.update(H.toBytes()[0..32]);
    hasher.update(xH.toBytes()[0..32]);
    hasher.update(kG.toBytes()[0..32]);
    hasher.update(kH.toBytes()[0..32]);
    hasher.final(&c);

    // r = v - c.x
    const cx = crypto.ecc.Ristretto255.scalar.mul(c, x);
    const s = crypto.ecc.Ristretto255.scalar.sub(k, cx);

    // Peggy sends s and c
    // Victor now computes:
    const sG = try crypto.ecc.Ristretto255.mul(G, s);
    const cY = try crypto.ecc.Ristretto255.mul(xG, c);
    const A = crypto.ecc.Ristretto255.add(sG, cY);

    const sH = try crypto.ecc.Ristretto255.mul(H, s);
    const cxH = try crypto.ecc.Ristretto255.mul(xH, c);
    const B = crypto.ecc.Ristretto255.add(sH, cxH);

    var c1: [crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    hasher = crypto.hash.sha2.Sha256.init(.{});
    hasher.update(G.toBytes()[0..32]);
    hasher.update(xG.toBytes()[0..32]);
    hasher.update(H.toBytes()[0..32]);
    hasher.update(xH.toBytes()[0..32]);
    hasher.update(A.toBytes()[0..32]);
    hasher.update(B.toBytes()[0..32]);
    hasher.final(&c1);

    // if c1 == c, it is proven!

    try stdout.print("Discrete Log Equivalence ZKP with Ristretto255\n", .{});
    try stdout.print("\nSecret (x) = {s}\n", .{secret});
    try stdout.print("\nH(x) = {x}\n", .{x});
    try stdout.print("\ns = {x}\n", .{s});
    try stdout.print("\nA = {x}\n", .{A.toBytes()});
    try stdout.print("\nB = {x}\n", .{B.toBytes()});
    try stdout.print("\nc = H(G || xG || H || xH || A || B) = {x}\n", .{c});
    try stdout.print("\nc' = H(G || xG || H || xH || A' || B') = {x}\n", .{c1});

    if (std.mem.eql(u8, c[0..32], c1[0..32])) {
        try stdout.print("\nZKP has been proven (c==c1)!\n", .{});
    } else {
        try stdout.print("\nZKP has NOT been proven (c!=c1)!\n", .{});
    }
    try stdout.flush();
}
