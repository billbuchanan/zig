const std = @import("std");
const crypto = @import("std").crypto;

pub const LipmaaResult = struct {
    i: i32,
    j: i32,
    k: i32,
    l: i32,
};

/// Brute-force search for i,j,k,l such that i^2 + j^2 + k^2 + l^2 == val.
/// Matches the Go behavior: returns the first found tuple, else all zeros.
pub fn lipmaa(val: i32) LipmaaResult {
    var i: i32 = 0;
    while (i < 100000) : (i += 1) {
        var j: i32 = 0;
        while (j < 1000) : (j += 1) {
            var k: i32 = 0;
            while (k < 100) : (k += 1) {
                var l: i32 = 0;
                while (l < 10) : (l += 1) {
                    const sum: i32 = (i * i) + (j * j) + (k * k) + (l * l);
                    if (sum == val) {
                        return .{ .i = i, .j = j, .k = k, .l = l };
                    }
                }
            }
        }
    }
    return .{ .i = 0, .j = 0, .k = 0, .l = 0 };
}
pub fn uintTo32Bytes(comptime T: type, value: T) [32]u8 {
    var out: [32]u8 = [_]u8{0} ** 32;
    var v = value;

    var i: usize = 0;
    while (v != 0 and i < 32) : (i += 1) {
        out[31 - i] = @intCast(v & 0xff);
        v >>= 8;
    }

    return out;
}

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

    const d = crypto.ecc.P256.scalar.Scalar.random();
    const Q = try crypto.ecc.P256.basePoint.mul(d.toBytes(std.builtin.Endian.big), std.builtin.Endian.big);

    //   k = curve.random_scalar()
    //   R = kG

    const k = crypto.ecc.P256.scalar.Scalar.random();
    const R = try crypto.ecc.P256.basePoint.mul(k.toBytes(std.builtin.Endian.big), std.builtin.Endian.big);

    // Compute c=H(R || Q || M)
    var e: [crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    var hasher = crypto.hash.sha2.Sha256.init(.{});
    hasher.update(R.toCompressedSec1()[0..32]);
    hasher.update(Q.toCompressedSec1()[0..32]);
    hasher.update(message);
    hasher.final(&e);

    // s = k + e.d
    const ed = try crypto.ecc.P256.scalar.mul(e, d.toBytes(std.builtin.Endian.big), std.builtin.Endian.big);
    const s = try crypto.ecc.P256.scalar.add(k.toBytes(std.builtin.Endian.big), ed, std.builtin.Endian.big);

    // Bob sends Alice (R,s)

    const sG = try crypto.ecc.P256.basePoint.mul(s, std.builtin.Endian.big);
    const eQ = try crypto.ecc.P256.mul(Q, e, std.builtin.Endian.big);
    const R_eQ = crypto.ecc.P256.add(R, eQ);

    try stdout.writeAll("Schnorr Signature\n");
    try stdout.print("\n Bob d= {x}\n", .{d.toBytes(std.builtin.Endian.big)});
    try stdout.print("\n Alice Q= {x}\n", .{Q.toCompressedSec1()});
    try stdout.print("\nR= {x}\n", .{R.toCompressedSec1()});
    try stdout.print("\ns= {x}\n", .{s});

    if (sG.equivalent(R_eQ)) {
        try stdout.writeAll("\nAlice has proven the signature\n");
    } else {
        try stdout.writeAll("\nAlice has NOT proven the signature\n");
    }

    try stdout.flush();
}
