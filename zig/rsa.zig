const std = @import("std");
const crypto = std.crypto;
pub const Numeric = struct {
    pub const primes = blk: {
        var result: [669]u16 = undefined;
        result[0] = 2;
        var index: usize = 1;
        @setEvalBranchQuota(19597);
        for (3..5000) |num| {
            var is_prime = true;
            for (0..index) |i| {
                if (num % result[i] == 0) {
                    is_prime = false;
                    break;
                }
                if (result[i] * result[i] > num) break;
            }

            if (is_prime) {
                if (index >= result.len) break;
                result[index] = num;
                index += 1;
            }
        }

        break :blk result;
    };

    fn mod_exp(T: type, base: T, exp: T, mod: T) T {
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

    fn miller_rabin_check(T: type, n: T, iterations: usize) bool {
        if (n <= 1) return false;
        if (n == 2 or n == 3) return true;
        if (n % 2 == 0) return false;

        var d: T = n - 1;
        var s: T = 0;
        while (d % 2 == 0) {
            d = @divTrunc(d, 2);
            s += 1;
        }

        var i: T = 0;
        while (i < iterations) : (i += 1) {
            const a = std.crypto.random.intRangeAtMost(T, 2, n - 2);
            var x = mod_exp(T, a, d, n);
            if (x == 1 or x == n - 1) continue;

            var is_composite = true;

            var j: T = 0;
            while (j < s - 1) : (j += 1) {
                x = mod_exp(T, x, 2, n);
                if (x == n - 1) {
                    is_composite = false;
                    break;
                }
            }
            if (is_composite) return false;
        }

        return true;
    }

    fn fermat_check(T: type, n: T, iter: usize) bool {
        if (n <= 1) return false;
        if (n == 2 or n == 3) return true;
        if (n % 2 == 0) return false;
        var i: T = 0;
        while (i < iter) : (i += 1) {
            const a = std.crypto.random.intRangeAtMost(T, 2, n - 2);
            if (mod_exp(T, a, n - 1, n) != 1) {
                return false;
            }
        }
        return true;
    }

    fn is_probably_prime(T: type, n: T, fiter: usize, mriter: usize) bool {
        if (!fermat_check(T, n, fiter)) {
            return false;
        }
        return miller_rabin_check(T, n, mriter);
    }

    const Args = struct { miller_rabin: usize = 5, fermat: usize = 5 };

    pub fn randomPrime(T: type, args: Args) T {
        const fiter: usize = args.fermat;
        const mriter: usize = args.miller_rabin;
        var number: T = undefined;
        prime_check: while (true) {
            number = crypto.random.int(T);
            number |= 1;
            low_prime_check: while (true) {
                for (primes) |prime| {
                    if (number == prime) return number;

                    const rem = number % prime;
                    if (rem == 0) {
                        number +%= 2;
                        continue :low_prime_check;
                    }
                }
                break :low_prime_check;
            }

            if (is_probably_prime(T, number, fiter, mriter)) {
                break :prime_check;
            }
        }
        return number;
    }

    fn gcd(T: type, a: T, b: T) T {
        var t_a = a;
        var t_b = b;
        var temp: T = undefined;
        while (true) {
            temp = t_a % t_b;
            if (temp == 0) {
                return t_b;
            }
            t_a = t_b;
            t_b = temp;
        }
    }

    fn modular_inverse(T: type, a: T, mod: T) ?T {
        if (gcd(T, a, mod) != 1) return null;
        const R = std.meta.Int(.signed, @typeInfo(T).int.bits * 2);
        const S = std.meta.Int(.unsigned, @typeInfo(T).int.bits * 2);

        const m0: R = mod;
        var y: R = 0;
        var x: R = 1;
        if (mod == 1) return 0;

        var A: R = a;
        var M: R = mod;

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
};

const PaddedSlice = struct {
    slice: []const u8,
    padding: u8,
    index: usize,

    pub fn init(slice: []const u8, padding: u8) @This() {
        return @This(){
            .slice = slice,
            .padding = padding,
            .index = 0,
        };
    }

    pub fn readByte(self: *@This()) u8 {
        const index = self.index;
        self.index += 1;
        if (index >= self.slice.len) {
            return self.padding;
        }
        return self.slice[index];
    }

    pub fn copy(self: *@This(), to: []u8) void {
        for (0..to.len) |i| {
            to[i] = self.readByte();
        }
    }

    pub fn reset(self: *@This()) void {
        self.index = 0;
    }
};

pub fn RSA(T: type) type {
    const R = std.meta.Int(.unsigned, @typeInfo(T).int.bits * 2);
    const BlockSizeT = @divExact(@typeInfo(T).int.bits, 8);
    const BlockSizeR = @divExact(@typeInfo(R).int.bits, 8);
    return struct {
        pub_k: [2]R,
        priv_k: [3]R,

        pub fn try_init(p: T, q: T) !@This() {
            if (p == q) return error.InvalidInput;
            const n: R = @as(R, p) * @as(R, q);
            const phi_n: R = @as(R, p - 1) * @as(R, q - 1);

            var e: R = crypto.random.intRangeAtMost(R, 2, phi_n - 1);
            while (Numeric.gcd(R, e, phi_n) != 1) {
                e = crypto.random.intRangeAtMost(R, 2, phi_n - 1);
            }
            const d = Numeric.modular_inverse(R, e, phi_n) orelse return error.NoModularInverse;

            return .{
                .priv_k = .{ p, q, d },
                .pub_k = .{ n, e },
            };
        }

        pub fn init(p: T, q: T) @This() {
            var temp: ?@This() = try_init(p, q) catch null;
            while (temp == null) {
                temp = try_init(p, q) catch null;
            }
            return temp.?;
        }

        fn encryptSingle(self: @This(), m: T) !R {
            const n = self.pub_k[0];
            const e = self.pub_k[1];
            if (m >= n) return error.MessageTooLarge;
            return Numeric.mod_exp(R, m, e, n);
        }
        fn decryptSingle(self: @This(), c: R) !T {
            const p = self.priv_k[0];
            const q = self.priv_k[1];
            const d = self.priv_k[2];
            const n = p * q;
            if (c >= n) return error.CipherTooLarge;
            return @truncate(Numeric.mod_exp(R, c, d, n));
        }

        fn encryptBlock(self: @This(), msg: *[BlockSizeT]u8, cph: *[BlockSizeR]u8) !void {
            const msg_num = std.mem.readInt(T, msg, .little);
            const encrypted = try self.encryptSingle(msg_num);
            std.mem.writeInt(R, cph, encrypted, .little);
        }
        fn decryptBlock(self: @This(), cph: *[BlockSizeR]u8, msg: *[BlockSizeT]u8) !void {
            const cph_num = std.mem.readInt(R, cph, .little);
            const decrypted = try self.decryptSingle(cph_num);
            std.mem.writeInt(T, msg, decrypted, .little);
        }

        pub fn encrypt(self: @This(), msg: []const u8, alloc: std.mem.Allocator) ![]u8 {
            const blocks = try std.math.divCeil(usize, msg.len, BlockSizeT);
            var out = try std.ArrayList(u8).initCapacity(alloc, blocks * BlockSizeR);

            const out_writer = out.writer(alloc);
            errdefer out.deinit(alloc);
            var slice = PaddedSlice.init(msg, 0);
            var msg_buffer: [BlockSizeT]u8 = undefined;
            var cph_buffer: [BlockSizeR]u8 = undefined;
            for (0..blocks) |_| {
                slice.copy(&msg_buffer);
                try self.encryptBlock(&msg_buffer, &cph_buffer);
                try out_writer.writeAll(&cph_buffer);
            }
            return out.toOwnedSlice(alloc);
        }
        pub fn decrypt(self: @This(), cph: []const u8, alloc: std.mem.Allocator) ![]u8 {
            const blocks = std.math.divExact(usize, cph.len, BlockSizeR) catch return error.InvalidCipherSize;
            var out = try std.ArrayList(u8).initCapacity(alloc, blocks * BlockSizeT);
            const out_writer = out.writer(alloc);
            errdefer out.deinit(alloc);
            var slice = PaddedSlice.init(cph, 0);
            var cph_buffer: [BlockSizeR]u8 = undefined;
            var msg_buffer: [BlockSizeT]u8 = undefined;
            for (0..blocks) |_| {
                slice.copy(&cph_buffer);
                try self.decryptBlock(&cph_buffer, &msg_buffer);
                try out_writer.writeAll(&msg_buffer);
            }
            return out.toOwnedSlice(alloc);
        }
    };
}
