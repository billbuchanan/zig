const std = @import("std");
const crypto = @import("std").crypto;

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
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    var xval: u32 = 5;
    var yval: u32 = 5;

    // Check if there are any arguments
    if (args.len > 1) {
        xval = try std.fmt.parseInt(u32, args[1], 10);
    }
    if (args.len > 2) {
        yval = try std.fmt.parseInt(u32, args[2], 10);
    }

    //curve := curves.K256()
    //H := curve.Point.Generator()

    //argCount := len(os.Args[1:])

    const x = try crypto.ecc.P256.scalar.Scalar.fromBytes(uintTo32Bytes(u32, xval), std.builtin.Endian.big);
    const y = try crypto.ecc.P256.scalar.Scalar.fromBytes(uintTo32Bytes(u32, yval), std.builtin.Endian.big);

    // x := curve.Scalar.New(xval)
    // y := curve.Scalar.New(yval)
    const r = crypto.ecc.P256.scalar.Scalar.random();
    const s = crypto.ecc.P256.scalar.Scalar.random();
    const a = crypto.ecc.P256.scalar.Scalar.random();
    const b = crypto.ecc.P256.scalar.Scalar.random();
    const alpha = crypto.ecc.P256.scalar.Scalar.random();
    const beta = crypto.ecc.P256.scalar.Scalar.random();

    // G := H.Mul(a.Mul(b))
    // Gamma := H.Mul(alpha.Mul(beta))

    const G = try crypto.ecc.P256.basePoint.mul(a.mul(b).toBytes(std.builtin.Endian.big), std.builtin.Endian.big);
    const Gamma = try crypto.ecc.P256.basePoint.mul(alpha.mul(beta).toBytes(std.builtin.Endian.big), std.builtin.Endian.big);

    // Pa := Gamma.Mul(r)
    // Pb := Gamma.Mul(s)

    const Pa = try crypto.ecc.P256.mul(Gamma, r.toBytes(std.builtin.Endian.big), std.builtin.Endian.big);
    const Pb = try crypto.ecc.P256.mul(Gamma, s.toBytes(std.builtin.Endian.big), std.builtin.Endian.big);

    // Qa := H.Mul(r).Add(G.Mul(x))
    // Qb := H.Mul(s).Add(G.Mul(y))

    const rH = try crypto.ecc.P256.basePoint.mul(r.toBytes(std.builtin.Endian.big), std.builtin.Endian.big);
    const Gx = try crypto.ecc.P256.mul(G, x.toBytes(std.builtin.Endian.big), std.builtin.Endian.big);
    const Qa = crypto.ecc.P256.add(rH, Gx);

    const sH = try crypto.ecc.P256.basePoint.mul(s.toBytes(std.builtin.Endian.big), std.builtin.Endian.big);
    const Gy = try crypto.ecc.P256.mul(G, y.toBytes(std.builtin.Endian.big), std.builtin.Endian.big);

    const Qb = crypto.ecc.P256.add(sH, Gy);

    // Qa := H.Mul(r).Add(G.Mul(x))
    // Qb := H.Mul(s).Add(G.Mul(y))

    const Qa_Qb = crypto.ecc.P256.sub(Qa, Qb);
    const c = try crypto.ecc.P256.mul(Qa_Qb, alpha.mul(beta).toBytes(std.builtin.Endian.big), std.builtin.Endian.big);
    const c_ = crypto.ecc.P256.sub(Pa, Pb);

    // c := Qa.Sub(Qb).Mul(alpha.Mul(beta))
    // c_ := Pa.Sub(Pb)

    try stdout.writeAll("Socialist Millionaire Problem\n");
    try stdout.print("\n Bob x= {x}\n", .{x.toBytes(std.builtin.Endian.big)});
    try stdout.print("\n Alice y= {x}\n", .{y.toBytes(std.builtin.Endian.big)});
    try stdout.print("\nc= {x}\n", .{c.toCompressedSec1()});
    try stdout.print("\nc_= {x}\n", .{c_.toCompressedSec1()});

    if (c.equivalent(c_)) {
        try stdout.writeAll("\nBob and Alice have the same money\n");
    } else {
        try stdout.writeAll("\nBob and Alice do NOT have the same money\n");
    }

    try stdout.flush();
}
