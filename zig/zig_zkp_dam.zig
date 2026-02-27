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


// nv := int(math.Pow(2, 19) - 1)
const nv = std.math.pow(u64, 2, 19)-1;

// curve := curves.K256()
// G := curve.Point.Generator()
const G = try crypto.ecc.P256.basePoint;



const v = crypto.ecc.P256.scalar.Scalar.random();

const H = try crypto.ecc.P256.basePoint.mul(uintTo32Bytes(u64,v), std.builtin.Endian.big);
  
const n = try crypto.ecc.P256.scalar.Scalar.fromBytes(nv, std.builtin.Endian.big);

const x0v, x1v, x2v, x3v = lipmaa(nv);
// v := curve.Scalar.Random(rand.Reader)
// H := G.Mul(v)

// n := curve.Scalar.New(nv)

// x0v, x1v, x2v, x3v := lipmaa(nv)


// r0 := curve.Scalar.Random(rand.Reader)
// r1 := curve.Scalar.Random(rand.Reader)
// r2 := curve.Scalar.Random(rand.Reader)
// r3 := curve.Scalar.Random(rand.Reader)
const r0 = crypto.ecc.P256.scalar.Scalar.random();
const r1 = crypto.ecc.P256.scalar.Scalar.random();
const r2 = crypto.ecc.P256.scalar.Scalar.random();
const r3 = crypto.ecc.P256.scalar.Scalar.random();

//	x0 := curve.Scalar.New(x0v)
//	x1 := curve.Scalar.New(x1v)
//	x2 := curve.Scalar.New(x2v)
//	x3 := curve.Scalar.New(x3v)

const x0 = try crypto.ecc.P256.scalar.Scalar.fromBytes(uintTo32Bytes(u64,x0v),std.builtin.Endian.big);
const x1 = try crypto.ecc.P256.scalar.Scalar.fromBytes(uintTo32Bytes(u64,x1v),std.builtin.Endian.big);
const x2 = try crypto.ecc.P256.scalar.Scalar.fromBytes(uintTo32Bytes(u64,x2v),std.builtin.Endian.big);
const x3 = try crypto.ecc.P256.scalar.Scalar.fromBytes(uintTo32Bytes(u64,x3v),std.builtin.Endian.big);



//	c0 := G.Mul(x0.Mul(x0)).Add(H.Mul(r0))
//	c1 := G.Mul(x1.Mul(x1)).Add(H.Mul(r1))
//	c2 := G.Mul(x2.Mul(x2)).Add(H.Mul(r2))
//	c3 := G.Mul(x3.Mul(x3)).Add(H.Mul(r3))

//	r := r0.Add(r1).Add(r2).Add(r3)
//	c := c0.Add(c1).Add(c2).Add(c3)

//	val := G.Mul(n).Add(H.Mul(r))




    // x := curve.Scalar.New(xval)
    // y := curve.Scalar.New(yval)

    const x = try crypto.ecc.P256.scalar.Scalar.fromBytes(uintTo32Bytes(u32, xval), std.builtin.Endian.big);
    const y = try crypto.ecc.P256.scalar.Scalar.fromBytes(uintTo32Bytes(u32, yval), std.builtin.Endian.big);




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
