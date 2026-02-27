const crypto = std.crypto;
const std = @import("std");

pub const PrimeError = error{
    InvalidBitLength,
};

pub fn randomPrimeU256(bits: u16, rounds: u8) PrimeError!u256 {
    if (bits < 2 or bits > 256) return PrimeError.InvalidBitLength;

    var rnd = std.crypto.random;

    while (true) {
        const n = randomOddWithExactBitsU256(&rnd, bits);

        // Filter quickly
        if (!passesSmallPrimeSieveU256(n)) continue;

        // Probable prime test
        if (isProbablePrimeMillerRabinU256(&rnd, n, rounds)) return n;
    }
}

/// --- helpers ---
fn randomOddWithExactBitsU256(rnd: *std.Random, bits: u16) u256 {
    var buf: [32]u8 = undefined;
    rnd.bytes(&buf);

    // Read full 256 bits, then mask down to `bits`
    var x: u256 = std.mem.readInt(u256, &buf, .big);

    // Mask to exactly `bits` bits
    x &= maskLowerBitsU256(bits);

    // Ensure top bit set so we really have `bits` bits
    x |= (@as(u256, 1) << @intCast(bits - 1));

    // Ensure odd
    x |= 1;

    return x;
}

fn maskLowerBitsU256(bits: u16) u256 {
    if (bits == 256) return ~@as(u256, 0);
    // (1<<bits)-1 is safe because bits in 0..255 here
    return (@as(u256, 1) << @intCast(bits)) - 1;
}

fn passesSmallPrimeSieveU256(n: u256) bool {
    // n is odd by construction; just remove obvious small factors
    const small_primes = [_]u16{
        3,   5,   7,   11,  13,  17,  19, 23, 29, 31, 37,  41,  43,  47,
        53,  59,  61,  67,  71,  73,  79, 83, 89, 97, 101, 103, 107, 109,
        113, 127, 131, 137, 139, 149,
    };

    inline for (small_primes) |p| {
        if (n % p == 0) return false;
    }
    return true;
}

fn isProbablePrimeMillerRabinU256(rnd: *std.Random, n: u256, rounds: u8) bool {
    // Handle tiny cases
    if (n < 4) return n == 2 or n == 3;
    if ((n & 1) == 0) return false;

    // Write n-1 = d * 2^s with d odd
    const nm1: u256 = n - 1;
    var d: u256 = nm1;
    var s: u32 = 0;
    while ((d & 1) == 0) : (s += 1) {
        d >>= 1;
    }

    var i: u8 = 0;
    while (i < rounds) : (i += 1) {
        const a = randomBaseU256(rnd, n); // in [2, n-2]

        var x = modular_exponentiation(u256, a, d, n);
        if (x == 1 or x == nm1) continue;

        var r: u32 = 1;
        var witnessed_composite = true;
        while (r < s) : (r += 1) {
            x = modMulU256(x, x, n);
            if (x == nm1) {
                witnessed_composite = false;
                break;
            }
            if (x == 1) return false;
        }
        if (witnessed_composite) return false;
    }

    return true;
}

fn randomBaseU256(rnd: *std.Random, n: u256) u256 {
    // pick a in [2, n-2]
    // Use simple reduction: a = 2 + (rand % (n-3)).
    // (For MR, slight modulo bias is fine; if you want, I can give rejection sampling.)
    var buf: [32]u8 = undefined;
    rnd.bytes(&buf);
    const r: u256 = std.mem.readInt(u256, &buf, .big);

    const range: u256 = n - 3; // >= 1 since n >= 5 for this path
    return 2 + (r % range);
}

fn modMulU256(a: u256, b: u256, m: u256) u256 {
    // Use u512 intermediates so we don't overflow.
    const prod: u512 = @as(u512, a) * @as(u512, b);
    const rem: u512 = prod % @as(u512, m);
    return @intCast(rem);
}

fn gcd(T: type, a: T, b: T) T {
    var temp_a = a;
    var temp_b = b;
    var temp: T = undefined;
    while (true) {
        temp = temp_a % temp_b;
        if (temp == 0) {
            return temp_b;
        }
        temp_a = temp_b;
        temp_b = temp;
    }
}
/// Compute a^{-1} (mod N)
/// Returns zero gcd(a, N) != 1
fn inverse_mod(T: type, a: T, N: T) ?T {
    if (gcd(T, a, N) != 1) return null;
    const R = std.meta.Int(.signed, @typeInfo(T).int.bits * 2);
    const S = std.meta.Int(.unsigned, @typeInfo(T).int.bits * 2);

    const m0: R = N;
    var y: R = 0;
    var x: R = 1;
    if (N == 1) return 0;

    var A: R = a;
    var M: R = N;

    while (A > 1) {
        const q: R = @divTrunc(A, M);
        var t: R = M;

        M = @rem(A, M);
        A = t;

        t = y;
        y = x - q * y;
        x = t;
    }

    if (x < 0) x += m0;

    return @truncate(@as(S, @intCast(x)));
}

fn modular_exponentiation(T: type, base: T, exp: T, mod: T) T {
    const R = std.meta.Int(.unsigned, @typeInfo(T).int.bits * 2);
    var b: R = base % mod;
    var e = exp;

    var r: R = 1;
    while (e > 0) {
        if (e % 2 == 1) {
            r = (r * b) % mod;
        }
        b = (b * b) % mod;
        e = @divTrunc(e, 2);
    }
    return @truncate(r);
}
pub fn main() !void {
    var stdoutemp_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdoutemp_buffer);
    const stdout = &stdout_writer.interface;

    var M: u256 = 9999;
    const e: u256 = 65537;

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    // Check if there are any arguments
    if (args.len > 1) {
        M = try std.fmt.parseInt(u256, args[1], 10);
    }
    const p: u256 = try randomPrimeU256(128, 14);
    const q: u256 = try randomPrimeU256(128, 14);
    const N: u256 = p * q;
    const PHI: u256 = (p - 1) * (q - 1);

    try stdout.print("GCD(e,PHI)=\t{}\n", .{gcd(u256, e, PHI)});
    try stdout.flush();

    const C: u512 = modular_exponentiation(u256, M, e, N);

    const d = inverse_mod(u512, e, PHI) orelse return error.NoModularInverse;
    const M1: u512 = modular_exponentiation(u512, C, d, N);

    try stdout.print("M={}\n\np={}\nq={}\nN={}\nPHI={}\n\nC={}\n\nDecrypt={}\n", .{ M, p, q, N, PHI, C, M1 });

    try stdout.flush();
}
