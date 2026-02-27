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
    const d = crypto.ecc.P384.scalar.Scalar.random();
    const Q = try crypto.ecc.P384.basePoint.mul(d.toBytes(std.builtin.Endian.big), std.builtin.Endian.big);

    //   k = curve.random_scalar()
    //   R = kG

    const k = crypto.ecc.P384.scalar.Scalar.random();
    const R = try crypto.ecc.P384.basePoint.mul(k.toBytes(std.builtin.Endian.big), std.builtin.Endian.big);

    // Compute c=H(R || Q || M)
    var e: [crypto.hash.sha2.Sha384.digest_length]u8 = undefined;
    var hasher = crypto.hash.sha2.Sha384.init(.{});
    hasher.update(R.toCompressedSec1()[0..32]);
    hasher.update(Q.toCompressedSec1()[0..32]);
    hasher.update(message);
    hasher.final(&e);

    // s = k + e.d
    const ed = try crypto.ecc.P384.scalar.mul(e, d.toBytes(std.builtin.Endian.big), std.builtin.Endian.big);
    const s = try crypto.ecc.P384.scalar.add(k.toBytes(std.builtin.Endian.big), ed, std.builtin.Endian.big);

    // Bob sends Alice (R,s). Now Alice uses Bob's public key (Q) to verify

    const sG = try crypto.ecc.P384.basePoint.mul(s, std.builtin.Endian.big);
    const eQ = try crypto.ecc.P384.mul(Q, e, std.builtin.Endian.big);
    const R_eQ = crypto.ecc.P384.add(R, eQ);

    try stdout.writeAll("Schnorr Signature with P384\n");
    try stdout.print("\nMessage= {s}\n", .{message});

    try stdout.print("\nBob's private d= {x}\n", .{d.toBytes(std.builtin.Endian.big)});
    try stdout.print("Bob's public Q= {x}\n", .{Q.toCompressedSec1()});
    try stdout.print("\nk= {x}\n", .{k.toBytes(std.builtin.Endian.big)});
    try stdout.print("\nR= {x}\n", .{R.toCompressedSec1()});
    try stdout.print("\ns= {x}\n", .{s});

    if (sG.equivalent(R_eQ)) {
        try stdout.writeAll("\nAlice has proven the signature\n");
    } else {
        try stdout.writeAll("\nAlice has NOT proven the signature\n");
    }

    try stdout.flush();
}
