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

    const G = crypto.ecc.P256.basePoint;

    const xG = try crypto.ecc.P256.basePoint.mul(x, std.builtin.Endian.big);

    // Random value v, and compute [v]G
    var v: [32]u8 = undefined;
    crypto.random.bytes(&v);
    const vG = try crypto.ecc.P256.basePoint.mul(v, std.builtin.Endian.big);

    // Compute c=H(G || [x]G || [v]G)
    var c: [crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    var hasher = crypto.hash.sha2.Sha256.init(.{});
    hasher.update(G.toCompressedSec1()[0..32]);
    hasher.update(xG.toCompressedSec1()[0..32]);
    hasher.update(vG.toCompressedSec1()[0..32]);
    hasher.final(&c);

    // r = v - c.x
    const cx = try crypto.ecc.P256.scalar.mul(c, x, std.builtin.Endian.big);
    const r = try crypto.ecc.P256.scalar.sub(v, cx, std.builtin.Endian.big);

    const rG = try crypto.ecc.P256.basePoint.mul(r, std.builtin.Endian.big);
    const cxG = try crypto.ecc.P256.mul(xG, c, std.builtin.Endian.big);

    // Vcheck = [r]G + [cx]G
    const Vcheck = crypto.ecc.P256.add(rG, cxG);

    try stdout.print("Fiat Shamir ZKP with P256\n", .{});
    try stdout.print("\nSecret (x) = {s}\n", .{secret});
    try stdout.print("\nH(x) = {x}\n", .{x});
    try stdout.print("\nc = H(G || xG || vG) = {x}\n", .{c});
    try stdout.print("\nr = {x}\n", .{r});
    try stdout.print("\nxG = {x}\n", .{xG.toCompressedSec1()});
    try stdout.print("\nvG = {x}\n", .{vG.toCompressedSec1()});
    try stdout.print("\nVcheck = {x}\n", .{Vcheck.toCompressedSec1()});

    if (Vcheck.equivalent(vG)) {
        try stdout.print("\nZKP has been proven (Vcheck==vG)!\n", .{});
    } else {
        try stdout.print("\nZKP has NOT been proven (Vcheck!=vG)!\n", .{});
    }
    try stdout.flush();
}
