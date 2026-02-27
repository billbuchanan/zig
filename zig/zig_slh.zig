const std = @import("std");

const c = @cImport({
    @cInclude("oqs.h");
});

fn cStrToSlice(cs: [*c]const u8) []const u8 {
    return std.mem.span(cs);
}

fn pickAlg(preferred: []const []const u8) ?[]const u8 {
    const n: usize = @intCast(c.OQS_SIG_alg_count());
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const id_cs = c.OQS_SIG_alg_identifier(@intCast(i));
        if (id_cs == null) continue;
        const id = cStrToSlice(id_cs);

        for (preferred) |needle| {
            if (std.mem.indexOf(u8, id, needle) != null) return id;
        }
    }
    return null;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    // stdout (Zig 0.16 style)
    var out_buf: [1024]u8 = undefined;
    var out_writer = std.fs.File.stdout().writer(&out_buf);
    const out = &out_writer.interface;

    // Optional CLI:
    //   argv[1] = exact liboqs alg identifier (e.g. "SLH-DSA-...") OR "auto"
    //   argv[2] = message
    const requested_alg: ?[]const u8 =
        if (args.len >= 2 and !std.mem.eql(u8, args[1], "auto")) args[1] else null;

    const message: []const u8 =
        if (args.len >= 3) args[2] else "hello from Zig + liboqs (SLH-DSA/SPHINCS+)";

    var alg_id: []const u8 = undefined;

    if (requested_alg) |a| {
        alg_id = a;
    } else {
        // Prefer SLH-DSA (FIPS 205), then SPHINCS+ (Round-3 family name)
        alg_id = pickAlg(&.{ "SLH-DSA", "SPHINCS+" }) orelse {
            try out.print("No SLH-DSA/SPHINCS+ algorithms found in this liboqs build.\n", .{});
            try out.print("Tip: list algorithms with: ./slh_dsa_sig list\n", .{});
            return;
        };
    }

    if (args.len >= 2 and std.mem.eql(u8, args[1], "list")) {
        const n: usize = @intCast(c.OQS_SIG_alg_count());
        try out.print("liboqs signature algorithms ({d}):\n", .{n});
        var i: usize = 0;
        while (i < n) : (i += 1) {
            const id_cs = c.OQS_SIG_alg_identifier(@intCast(i));
            if (id_cs != null) {
                try out.print("  {s}\n", .{cStrToSlice(id_cs)});
            }
        }
        return;
    }

    // Create OQS_SIG object
    // Note: OQS_SIG_new expects a C string; we provide one via a 0-terminated buffer.
    var alg_z: [:0]u8 = try allocator.allocSentinel(u8, alg_id.len, 0);
    defer allocator.free(alg_z);
    @memcpy(alg_z[0..alg_id.len], alg_id);

    const sig = c.OQS_SIG_new(alg_z.ptr);
    if (sig == null) {
        try out.print("OQS_SIG_new failed for algorithm: {s}\n", .{alg_id});
        return;
    }
    defer c.OQS_SIG_free(sig);

    const pk_len: usize = @intCast(sig.*.length_public_key);
    const sk_len: usize = @intCast(sig.*.length_secret_key);
    const sig_max_len: usize = @intCast(sig.*.length_signature);

    var public_key = try allocator.alloc(u8, pk_len);
    defer allocator.free(public_key);

    var secret_key = try allocator.alloc(u8, sk_len);
    defer allocator.free(secret_key);
    // best-effort wipe
    defer std.crypto.utils.secureZero(u8, secret_key);

    var signature = try allocator.alloc(u8, sig_max_len);
    defer allocator.free(signature);

    try out.print("Algorithm: {s}\n", .{alg_id});
    try out.print("pk={d} bytes, sk={d} bytes, sig(max)={d} bytes\n", .{ pk_len, sk_len, sig_max_len });
    try out.print("Message: \"{s}\"\n", .{message});

    // Keypair
    if (c.OQS_SIG_keypair(sig, public_key.ptr, secret_key.ptr) != c.OQS_SUCCESS) {
        try out.print("Keypair generation failed\n", .{});
        return;
    }

    // Sign
    var sig_len_c: usize = 0;
    if (c.OQS_SIG_sign(
        sig,
        signature.ptr,
        &sig_len_c,
        message.ptr,
        message.len,
        secret_key.ptr,
    ) != c.OQS_SUCCESS) {
        try out.print("Signing failed\n", .{});
        return;
    }
    const sig_len: usize = sig_len_c;
    try out.print("Signature length: {d} bytes\n", .{sig_len});

    // Verify
    const vrc = c.OQS_SIG_verify(
        sig,
        message.ptr,
        message.len,
        signature.ptr,
        sig_len,
        public_key.ptr,
    );

    if (vrc == c.OQS_SUCCESS) {
        try out.print("Verify: OK ✅\n", .{});
    } else {
        try out.print("Verify: FAILED ❌\n", .{});
    }
}
