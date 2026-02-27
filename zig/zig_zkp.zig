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

    const G = crypto.ecc.Secp256k1.basePoint;

    const xG = try crypto.ecc.Secp256k1.basePoint.mul(x, std.builtin.Endian.big);

    // Random value v, and compute [v]G
    var v: [32]u8 = undefined;
    crypto.random.bytes(&v);
    const vG = try crypto.ecc.Secp256k1.basePoint.mul(v, std.builtin.Endian.big);

    // Compute c=H(G || [x]G || [v]G)
    var chal: [crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    var hasher = crypto.hash.sha2.Sha256.init(.{});
    hasher.update(G.toCompressedSec1()[0..32]);
    hasher.update(xG.toCompressedSec1()[0..32]);
    hasher.update(vG.toCompressedSec1()[0..32]);
    hasher.final(&chal);

    const N = crypto.ff.Modulus(256);

    // Set to the order of the secp256k1 curve
    const n = try N.fromPrimitive(u256, 115792089237316195423570985008687907852837564279074904382605163141518161494337);

    const c = try N.Fe.fromBytes(n, &chal, std.builtin.Endian.big);
    const xval = try N.Fe.fromBytes(n, &x, std.builtin.Endian.big);
    const vval = try N.Fe.fromBytes(n, &v, std.builtin.Endian.big);

    // r=v - cx
    const cx = n.mul(c, xval);
    const r = n.sub(vval, cx);

    var rval: [32]u8 = undefined;
    try r.toBytes(rval[0..32], std.builtin.Endian.big);

    const rG = try crypto.ecc.Secp256k1.basePoint.mul(rval, std.builtin.Endian.big);
    const cxG = try crypto.ecc.Secp256k1.mul(xG, chal, std.builtin.Endian.big);

    // Vcheck = [r]G + [cx]G
    const Vcheck = crypto.ecc.Secp256k1.add(rG, cxG);

    try stdout.print("Fiat Shamir ZKP with secp256k1\n", .{});
    try stdout.print("\nSecret (x) = {s}\n", .{secret});
    try stdout.print("\nH(x) = {x}\n", .{x});
    try stdout.print("\nc = H(G || xG || vG) = {!}\n", .{c.toPrimitive(u256)});
    try stdout.print("\nr = {!}\n", .{r.toPrimitive(u256)});
    try stdout.print("\nxG = {x}\n", .{xG.toCompressedSec1()});
    try stdout.print("\nvG = {x}\n", .{vG.toCompressedSec1()});
    try stdout.print("\nVcheck = {x}\n", .{Vcheck.toCompressedSec1()});

    if (Vcheck.equivalent(vG)) {
        try stdout.print("ZKP has been proven (Vcheck==vG)!\n", .{});
    } else {
        try stdout.print("ZKP has NOT been proven (Vcheck!=vG)!\n", .{});
    }
    try stdout.flush();
}
