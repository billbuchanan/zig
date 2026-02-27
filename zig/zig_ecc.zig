const std = @import("std");
const crypto = @import("std").crypto;

pub fn main() !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    // create a seed for key pair generation
    var scalar: [32]u8 = undefined;
    crypto.random.bytes(&scalar);

    var scalar2: [48]u8 = undefined;
    crypto.random.bytes(&scalar2);

    const G1 = crypto.ecc.Curve25519.basePoint;
    const G2 = crypto.ecc.Edwards25519.basePoint;
    const G3 = crypto.ecc.P256.basePoint;
    const G4 = crypto.ecc.P384.basePoint;
    const G5 = crypto.ecc.Ristretto255.basePoint;
    const G6 = crypto.ecc.Secp256k1.basePoint;

    const P1 = try crypto.ecc.Curve25519.basePoint.mul(scalar);
    const P2 = try crypto.ecc.Edwards25519.basePoint.mul(scalar);
    const P3 = try crypto.ecc.P256.basePoint.mul(scalar, std.builtin.Endian.big);
    const P4 = try crypto.ecc.P384.basePoint.mul(scalar2, std.builtin.Endian.big);
    const P5 = try crypto.ecc.Ristretto255.basePoint.mul(scalar);
    const P6 = try crypto.ecc.Secp256k1.basePoint.mul(scalar, std.builtin.Endian.big);

//    Alternative we could have used: 
//  const P1 = try crypto.ecc.Curve25519.mul(G1, scalar);
//  const P2 = try crypto.ecc.Edwards25519.mul(G1, scalar);
//  etc.

    try stdout.print("ECC: P=a.G\n", .{});
    try stdout.print("\na = {x}\n", .{scalar});
    try stdout.print("b = {x}\n", .{scalar2});

    try stdout.print("\nCurve25519 Base Point: {x}\n", .{crypto.ecc.Curve25519.toBytes(G1)});
    try stdout.print("  [a]G: {x}\n", .{crypto.ecc.Curve25519.toBytes(P1)});
    try stdout.print("\nEdwards25519 Base Point: {x}\n", .{crypto.ecc.Edwards25519.toBytes(G2)});
    try stdout.print("  [a]G: {x}\n", .{crypto.ecc.Edwards25519.toBytes(P2)});

    try stdout.print("\nP256 Base Point: {x}\n", .{crypto.ecc.P256.toUncompressedSec1(G3)});
    try stdout.print("  [a]G: {x}\n", .{crypto.ecc.P256.toUncompressedSec1(P3)});
    try stdout.print("\nP384 Base Point: {x}\n", .{crypto.ecc.P384.toUncompressedSec1(G4)});
    try stdout.print("  [a]G: {x}\n", .{crypto.ecc.P384.toUncompressedSec1(P4)});
    try stdout.print("\nRistretto255 Base Point: {x}\n", .{crypto.ecc.Ristretto255.toBytes(G5)});
    try stdout.print("  [a]G: {x}\n", .{crypto.ecc.Ristretto255.toBytes(P5)});
    try stdout.print("\nsecp256k1 Base Point: {x}\n", .{crypto.ecc.Secp256k1.toUncompressedSec1(G6)});
    try stdout.print("  [a]G: {x}\n", .{crypto.ecc.Secp256k1.toUncompressedSec1(P6)});
    try stdout.flush();
}
