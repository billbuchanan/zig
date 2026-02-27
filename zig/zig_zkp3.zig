const std = @import("std");
const crypto = @import("std").crypto;

pub fn main() !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    // create a secret
    var secret: []const u8 = undefined;
    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    // Check if there are any arguments
    if (args.len > 1) {
        secret = args[1];
    }

    var x: [crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    crypto.hash.sha2.Sha256.hash(secret, &x, .{});

    const G = crypto.ecc.Ristretto255.basePoint;

    const xG = try crypto.ecc.Ristretto255.basePoint.mul(x);

    // Random value v, and compute [v]G
    var v: [32]u8 = undefined;
    crypto.random.bytes(&v);

    const vG = try crypto.ecc.Ristretto255.basePoint.mul(v);

    // Compute c=H(G || [x]G || [v]G)
    var c: [crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    var hasher = crypto.hash.sha2.Sha256.init(.{});
    hasher.update(G.toBytes()[0..32]);
    hasher.update(xG.toBytes()[0..32]);
    hasher.update(vG.toBytes()[0..32]);
    hasher.final(&c);

    // r = v - c.x
    const cx = crypto.ecc.Ristretto255.scalar.mul(c, x);
    const r = crypto.ecc.Ristretto255.scalar.sub(v, cx);

    const rG = try crypto.ecc.Ristretto255.basePoint.mul(r);
    const cxG = try crypto.ecc.Ristretto255.mul(xG, c);

    // Vcheck = [r]G + [cx]G
    const Vcheck = crypto.ecc.Ristretto255.add(rG, cxG);

    try stdout.print("Fiat Shamir ZKP with Ristretto255\n", .{});
    try stdout.print("\nSecret (x) = {s}\n", .{secret});
    try stdout.print("\nH(x)= {x}\n", .{x});
    try stdout.print("\nc = H(G || xG || vG) =  {x}\n", .{c});
    try stdout.print("\nr = {x}\n", .{r});
    try stdout.print("\nxG = {x}\n", .{xG.toBytes()});
    try stdout.print("\nvG = {x}\n", .{vG.toBytes()});
    try stdout.print("\nVcheck = {x}\n", .{Vcheck.toBytes()});

    if (Vcheck.equivalent(vG)) {
        try stdout.print("\nZKP has been proven (Vcheck==vG)!\n", .{});
    } else {
        try stdout.print("\nZKP has NOT been proven (Vcheck!=vG)!\n", .{});
    }
    try stdout.flush();
}
