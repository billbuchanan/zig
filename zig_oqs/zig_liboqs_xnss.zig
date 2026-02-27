const std = @import("std");

const c = @cImport({
    @cInclude("oqs/oqs.h");
});

fn oqsCheck(rc: c_int, what: []const u8) !void {
    if (rc == c.OQS_SUCCESS) return;
    std.debug.print("{s} failed (rc={d})\n", .{ what, rc });
    return error.OqsError;
}

fn printHex(writer: anytype, label: []const u8, data: []const u8) !void {
    try writer.print("{s} ({d} bytes): ", .{ label, data.len });
    for (data) |b| try writer.print("{x:0>2}", .{b});
    try writer.writeByte('\n');
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Zig 0.15.2 stdout writer pattern
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    // Defaults chosen from the liboqs docs pages for XMSS and LMS parameter set identifiers.
    // XMSS examples include "XMSS-SHA2_10_256". :contentReference[oaicite:1]{index=1}
    // LMS examples include "LMS_SHA256_H5_W4". :contentReference[oaicite:2]{index=2}
    const xmss_alg: []const u8 = args[2];
    //  const lms_alg: []const u8 = if (args.len >= 3) args[2] else "LMS_SHA256_H5_W4";
    const msg: []const u8 = args[1];

    // Ensure NUL-terminated C string for OQS_SIG_new
    const alg_z = try std.fmt.allocPrint(allocator, "{s}", .{xmss_alg});
    defer allocator.free(alg_z);

    const sig_obj = c.OQS_SIG_new(alg_z.ptr);
    if (sig_obj == null) {
        try stdout.print("Can't find: {s}\n", .{xmss_alg});
        try stdout.flush();
    }

    defer c.OQS_SIG_free(sig_obj);

    const pk_len: usize = sig_obj.*.length_public_key;
    try stdout.print("Algorithm: {s}\n", .{xmss_alg});
    try stdout.flush();
    const sk_len: usize = sig_obj.*.length_secret_key;
    try stdout.print("Algorithm: {s}\n", .{xmss_alg});
    try stdout.flush();
    const sig_len_max: usize = sig_obj.*.length_signature;

    try stdout.print("Algorithm: {s}\n", .{xmss_alg});
    try stdout.flush();

    var pk = try allocator.alloc(u8, pk_len);
    defer allocator.free(pk);

    // IMPORTANT: sk must be mutable because stateful schemes update it after signing.
    var sk = try allocator.alloc(u8, sk_len);
    defer allocator.free(sk);

    try oqsCheck(c.OQS_SIG_keypair(sig_obj, pk.ptr, sk.ptr), "OQS_SIG_keypair");

    // Sign (stateful: sk is updated IN PLACE by liboqs for XMSS/LMS)
    var signature = try allocator.alloc(u8, sig_len_max);
    defer allocator.free(signature);

    var sig_len: usize = 0;
    try oqsCheck(
        c.OQS_SIG_sign(sig_obj, signature.ptr, &sig_len, msg.ptr, msg.len, sk.ptr),
        "OQS_SIG_sign",
    );
    const sig = signature[0..sig_len];

    // Verify
    const vrc = c.OQS_SIG_verify(sig_obj, msg.ptr, msg.len, sig.ptr, sig.len, pk.ptr);
    const ok = (vrc == c.OQS_SUCCESS);

    try stdout.print("Algorithm: {s}\n", .{xmss_alg});
    try stdout.print("Message: {s}\n", .{msg});
    try stdout.print("Verify: {s}\n", .{if (ok) "OK" else "FAIL"});

    if (sk_len > 200) {
        try stdout.print("Private key (first 200 bytes): {x} Length: {d}\n\n", .{ sk[0..200], sk_len });
    } else try stdout.print("Private key: {x} Length: {d}\n\n", .{ sk, sk_len });

    if (pk_len > 200) {
        try stdout.print("Public key (first 200 bytes): {x} Length: {d}\n\n", .{ pk[0..200], pk_len });
    } else try stdout.print("Private key: {x} Length: {d}\n\n", .{ pk, pk_len });

    if (sig.len > 200) {
        try stdout.print("Signature (first 200 bytes): {x} Length: {d}\n\n", .{ signature[0..200], sig_len });
    } else try stdout.print("Private key: {x} Length: {d}\n\n", .{ sig, sig.len });

    try stdout.print("Verify: {s}\n\n", .{if (ok) "OK" else "FAIL"});

    try stdout.flush();
}
