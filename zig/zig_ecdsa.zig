const std = @import("std");
const crypto = @import("std").crypto;

pub fn main() !void {
    var message: []u8 = undefined;

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    // Check if there are any arguments
    if (args.len > 1) {
        message = args[1];
    }

    // Bob generates his private key (d) and public key (Q)
    const d = crypto.ecc.Secp256k1.scalar.Scalar.random();
    const Q = try crypto.ecc.Secp256k1.basePoint.mul(d.toBytes(std.builtin.Endian.big), std.builtin.Endian.big);

    var h: [crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    var hasher = crypto.hash.sha2.Sha256.init(.{});
    hasher.update(message);
    hasher.final(&h);

    const z = try crypto.ecc.Secp256k1.scalar.Scalar.fromBytes(h, std.builtin.Endian.big);

    const k = crypto.ecc.Secp256k1.scalar.Scalar.random();
    const kG = try crypto.ecc.Secp256k1.basePoint.mul(k.toBytes(std.builtin.Endian.big), std.builtin.Endian.big);

    const r = try crypto.ecc.Secp256k1.scalar.Scalar.fromBytes(kG.affineCoordinates().x.toBytes(std.builtin.Endian.big), std.builtin.Endian.big);
    //   const r = kG_x;

    const k_inv = k.invert();

    const s = k_inv.mul(z.add(r.mul(d)));

    // Bob passes (r,s)

    // u_1 = z.s^{-1}
    const u_1 = z.mul(s.invert());
    // u_2 = r.s^{-1}
    const u_2 = r.mul(s.invert());
    // P = [u_1]G + [u_2]Q
    const u1G = try crypto.ecc.Secp256k1.basePoint.mul(u_1.toBytes(std.builtin.Endian.big), std.builtin.Endian.big);
    const u2Q = try crypto.ecc.Secp256k1.mul(Q, u_2.toBytes(std.builtin.Endian.big), std.builtin.Endian.big);
    const P = crypto.ecc.Secp256k1.add(u1G, u2Q);

    // r_x= P_x (mod n)
    const r_x = P.affineCoordinates().x.toBytes(std.builtin.Endian.big);

    try stdout.writeAll("ECDSA Secp256k1\n");
    try stdout.print("\nMessage= {s}\n", .{message});

    try stdout.print("\nBob's private d= {x}\n", .{d.toBytes(std.builtin.Endian.big)});
    try stdout.print("\nBob's public Q= {x}\n", .{Q.toCompressedSec1()});

    try stdout.print("\ns= {x}\n", .{s.toBytes(std.builtin.Endian.big)});
    try stdout.print("\nr= {x}\n", .{r.toBytes(std.builtin.Endian.big)});

    try stdout.print("\nAlice hashes the message, and uses (r,s) and Bob's public key\n", .{});
    try stdout.print("\nr_x= {x}\n", .{r_x});

    if (std.mem.eql(u8, r.toBytes(std.builtin.Endian.big)[0..32], r_x[0..32])) {
        try stdout.writeAll("\nAlice has proven the signature\n");
    } else {
        try stdout.writeAll("\nAlice has NOT proven the signature\n");
    }

    try stdout.flush();
}
