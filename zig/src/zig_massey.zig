const crypto = std.crypto;
const std = @import("std");

pub const PrimeError = error{
    InvalidBitLength,
};

/// Generate a random probable prime as u256 with exactly `bits` bits (2..256).
/// `rounds`: Miller–Rabin rounds (e.g. 16/24/32).
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

        var x = modPowU256(a, d, n);
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

fn modPowU256(base: u256, exp: u256, m: u256) u256 {
    var result: u256 = 1;
    var b: u256 = base % m;
    var e: u256 = exp;

    while (e != 0) {
        if ((e & 1) == 1) result = modMulU256(result, b, m);
        e >>= 1;
        if (e != 0) b = modMulU256(b, b, m);
    }
    return result;
}

pub fn main() !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    const P = try randomPrimeU256(256, 24);

    const p: comptime_int = (comptime_int) P;

    try stdout.print("ChaCha20 Commutative Encryption\n", .{});
    try stdout.print("Prime {}\n", .{p});

    try stdout.flush();
}
