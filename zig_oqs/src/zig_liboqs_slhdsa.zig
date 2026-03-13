const std = @import("std");

const c = @cImport({
    @cInclude("oqs/oqs.h");
    @cInclude("oqs/sig_stfl.h");
});

fn oqsOk(status: c.OQS_STATUS, what: []const u8) !void {
    if (status == c.OQS_SUCCESS) return;
    std.debug.print("{s} failed\n", .{what});
    return error.OqsError;
}

fn printHex(w: anytype, label: []const u8, data: []const u8) !void {
    try w.print("{s} ({d} bytes): ", .{ label, data.len });
    for (data) |b| try w.print("{x:0>2}", .{b});
    try w.writeByte('\n');
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var stdout_buffer: [8192]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const out = &stdout_writer.interface;

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    // Pick any XMSS identifier your liboqs build enables.
    const alg_name: []const u8 = if (args.len >= 2)
        args[1]
    else
        "XMSS-SHA2_10_256";

    const msg: []const u8 = if (args.len >= 3)
        args[2]
    else
        "Hello from Zig + liboqs XMSS";

    const alg_z = try std.fmt.allocPrintZ(allocator, "{s}", .{alg_name});
    defer allocator.free(alg_z);

    if (c.OQS_SIG_STFL_alg_is_enabled(alg_z.ptr) != 1) {
        std.debug.print("XMSS algorithm not enabled in this liboqs build: {s}\n", .{alg_name});
        return error.AlgorithmUnavailable;
    }

    const sig = c.OQS_SIG_STFL_new(alg_z.ptr);
    if (sig == null) {
        std.debug.print("OQS_SIG_STFL_new failed for: {s}\n", .{alg_name});
        return error.AlgorithmUnavailable;
    }
    defer c.OQS_SIG_STFL_free(sig);

    const sk = c.OQS_SIG_STFL_SECRET_KEY_new(alg_z.ptr);
    if (sk == null) {
        std.debug.print("OQS_SIG_STFL_SECRET_KEY_new failed for: {s}\n", .{alg_name});
        return error.OutOfMemory;
    }
    defer c.OQS_SIG_STFL_SECRET_KEY_free(sk);

    const public_key = try allocator.alloc(u8, sig.*.length_public_key);
    defer allocator.free(public_key);

    const signature = try allocator.alloc(u8, sig.*.length_signature);
    defer allocator.free(signature);

    var signature_len: usize = 0;

    try oqsOk(
        c.OQS_SIG_STFL_keypair(sig, public_key.ptr, sk),
        "OQS_SIG_STFL_keypair",
    );

    try oqsOk(
        c.OQS_SIG_STFL_sign(
            sig,
            signature.ptr,
            &signature_len,
            msg.ptr,
            msg.len,
            sk,
        ),
        "OQS_SIG_STFL_sign",
    );

    try oqsOk(
        c.OQS_SIG_STFL_verify(
            sig,
            msg.ptr,
            msg.len,
            signature.ptr,
            signature_len,
            public_key.ptr,
        ),
        "OQS_SIG_STFL_verify",
    );

    var remaining: c_ulonglong = 0;
    var total: c_ulonglong = 0;
    _ = c.OQS_SIG_STFL_sigs_remaining(sig, &remaining, sk);
    _ = c.OQS_SIG_STFL_sigs_total(sig, &total, sk);

    try out.print("Algorithm: {s}\n", .{alg_name});
    try out.print("Message:   {s}\n", .{msg});
    try out.print("Remaining signatures: {d}", .{remaining});
    if (total != 0) {
        try out.print(" / {d}", .{total});
    }
    try out.print("\n\n", .{});

    try printHex(out, "Public key", public_key);
    try printHex(out, "Signature", signature[0..signature_len]);

    // Optional: serialize updated secret key state after signing.
    var sk_buf_ptr: [*c]u8 = null;
    var sk_buf_len: usize = 0;
    if (c.OQS_SIG_STFL_SECRET_KEY_serialize(&sk_buf_ptr, &sk_buf_len, sk) == c.OQS_SUCCESS and sk_buf_ptr != null) {
        defer c.OQS_MEM_secure_free(sk_buf_ptr, sk_buf_len);
        try out.print("Serialized secret-key state size: {d} bytes\n", .{sk_buf_len});
    }

    try out.flush();
}