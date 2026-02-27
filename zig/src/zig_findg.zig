const std = @import("std");
const crypto = @import("std").crypto;

fn distinctPrimeFactors(n_in: u64) std.ArrayList(u64) {
    var n = n_in;

    const allocator = std.heap.page_allocator;
    var factors = std.array_list.Managed(u64).init(allocator);

    if (n % 2 == 0) {
        try factors.append(2);

        while (n % 2 == 0) n /= 2;
    }

    var d: u64 = 3;
    while (d <= n / d) : (d += 2) {
        if (n % d == 0) {
            try factors.append(d);
            while (n % d == 0) n /= d;
        }
    }

    if (n > 1) {
        // Remaining prime factor
        try factors.append(n);
    }

    return factors;
}
fn isPrimeTrial(n: u64) bool {
    // Lightweight check; good for "given prime p" sanity.
    if (n < 2) return false;
    if (n % 2 == 0) return n == 2;
    if (n % 3 == 0) return n == 3;

    var i: u64 = 5;
    while (i <= n / i) : (i += 6) {
        if (n % i == 0) return false;
        if (n % (i + 2) == 0) return false;
    }
    return true;
}

fn isGeneratorModPrime(g_in: u64, p: u64) !bool {
    if (p < 3) return false; // group size p-1 is 1 or 2; not meaningful here
    if (!isPrimeTrial(p)) return false;

    const g = g_in % p;
    if (g == 0) return false;
    if (g == 1) return false;

    const phi: u64 = p - 1;

    const factors = distinctPrimeFactors(phi);
    //  defer factors.deinit();

    // Check: g^((p-1)/q) != 1 (mod p) for all prime factors q of p-1
    for (factors.items) |q| {
        const e = phi / q;
        if (powMod(g, e, p) == 1) return false;
    }
    return true;
}
fn powMod(base: u64, exp: u64, m: u64) u64 {
    var result: u64 = 1 % m;
    var b: u64 = base % m;
    var e: u64 = exp;

    while (e != 0) : (e >>= 1) {
        if ((e & 1) == 1) result = mulMod(result, b, m);
        b = mulMod(b, b, m);
    }
    return result;
}
fn mulMod(a: u64, b: u64, m: u64) u64 {
    // Safe for u64 using u128 intermediate.
    return @as(u64, @intCast((@as(u128, a) * @as(u128, b)) % @as(u128, m)));
}
pub fn main() !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    const p_str = "87";
    const g_str = "9";

    const p = try std.fmt.parseUnsigned(u64, p_str, 0);
    const g = try std.fmt.parseUnsigned(u64, g_str, 0);

    const ok = try isGeneratorModPrime(g, p);

    if (ok) {
        std.debug.print("YES: g={d} is a generator modulo prime p={d} (full-order element).\n", .{ g, p });
    } else {
        std.debug.print("NO:  g={d} is NOT a generator modulo prime p={d}.\n", .{ g, p });
    }
    try stdout.flush();
}
