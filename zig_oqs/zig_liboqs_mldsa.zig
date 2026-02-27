const std = @import("std");

const c = @cImport({
    @cInclude("oqs/oqs.h");
});

fn oqsCheck(rc: c_int, what: []const u8) !void {
    // OQS_SUCCESS == 0
    if (rc == c.OQS_SUCCESS) return;
    std.debug.print("{s} failed (rc={d})\n", .{ what, rc });
    return error.OqsError;
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

    const msg: []const u8 = args[1];

    // "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"
    const alg_name = args[2];

    // We need NUL-terminated C strings for OQS_SIG_new
    const alg_z = try std.fmt.allocPrint(allocator, "{s}", .{alg_name});
    defer allocator.free(alg_z);

    const sig_obj = c.OQS_SIG_new(alg_z.ptr);

    defer c.OQS_SIG_free(sig_obj);

    const pk_len: usize = sig_obj.*.length_public_key;
    const sk_len: usize = sig_obj.*.length_secret_key;
    const sig_len_max: usize = sig_obj.*.length_signature;

    const pk = try allocator.alloc(u8, pk_len);
    defer allocator.free(pk);
    const sk = try allocator.alloc(u8, sk_len);
    defer allocator.free(sk);

    // Generate Keypair (sk - private, pk -public)
    try oqsCheck(c.OQS_SIG_keypair(sig_obj, pk.ptr, sk.ptr), "OQS_SIG_keypair");

    // Sign a message with the private key (sk)
    var signature = try allocator.alloc(u8, sig_len_max);
    defer allocator.free(signature);

    var sig_len: usize = 0;
    try oqsCheck(
        c.OQS_SIG_sign(sig_obj, signature.ptr, &sig_len, msg.ptr, msg.len, sk.ptr),
        "OQS_SIG_sign",
    );
    signature = signature[0..sig_len];

    // Verify signature with the public key (pk)
    const vrc = c.OQS_SIG_verify(sig_obj, msg.ptr, msg.len, signature.ptr, signature.len, pk.ptr);
    const ok = (vrc == c.OQS_SUCCESS);

    try stdout.print("Liboqs. Algorithm: {s}\n", .{alg_name});
    try stdout.print("Message: {s}\n\n", .{msg});

    try stdout.print("Private key (first 200 bytes): {x} Length: {d}\n\n", .{ sk[0..200], sk_len });
    try stdout.print("Public key (first 200 bytes): {x} Length: {d}\n\n", .{ pk[0..200], pk_len });
    try stdout.print("Signature (first 200 bytes): {x} Length: {d}\n\n", .{ signature[0..200], sig_len });

    try stdout.print("Verify: {s}\n\n", .{if (ok) "OK" else "FAIL"});

    try stdout.flush();
}
