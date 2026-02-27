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

    // "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", etc
    const alg_name = args[1];

    // Ensure NUL-terminated C string for OQS_KEM_new
    const alg_z = try std.fmt.allocPrint(allocator, "{s}", .{alg_name});
    defer allocator.free(alg_z);

    const kem = c.OQS_KEM_new(alg_z.ptr);
    defer c.OQS_KEM_free(kem);

    if (kem == null) {
        try stdout.print("Cannot find algorithm: {s}\n", .{alg_name});
        try stdout.flush();
        return;
    }

    const pk_len: usize = kem.*.length_public_key;

    const sk_len: usize = kem.*.length_secret_key;

    const ct_len: usize = kem.*.length_ciphertext;

    const ss_len: usize = kem.*.length_shared_secret;

    var pk = try allocator.alloc(u8, pk_len);
    defer allocator.free(pk);
    var sk = try allocator.alloc(u8, sk_len);
    defer allocator.free(sk);

    // Generate keypair
    try oqsCheck(c.OQS_KEM_keypair(kem, pk.ptr, sk.ptr), "OQS_KEM_keypair");

    try stdout.print("Key pair created: {s}\n", .{alg_name});
    try stdout.flush();

    // Bob encapsulates for Alice
    var ct = try allocator.alloc(u8, ct_len);
    defer allocator.free(ct);
    const ss_sender = try allocator.alloc(u8, ss_len);
    defer allocator.free(ss_sender);

    try oqsCheck(c.OQS_KEM_encaps(kem, ct.ptr, ss_sender.ptr, pk.ptr), "OQS_KEM_encaps");

    // Alice decapsulates
    const ss_receiver = try allocator.alloc(u8, ss_len);
    defer allocator.free(ss_receiver);

    try oqsCheck(c.OQS_KEM_decaps(kem, ss_receiver.ptr, ct.ptr, sk.ptr), "OQS_KEM_decaps");

    const match = std.mem.eql(u8, ss_sender, ss_receiver);

    try stdout.print("Liboqs. Algorithm: {s}\n", .{alg_name});

    if (sk_len > 200) {
        try stdout.print("Private key (first 200 bytes): {x} Length: {d}\n\n", .{ sk[0..200], sk_len });
    } else try stdout.print("Private key: {x} Length: {d}\n\n", .{ sk, sk_len });

    if (pk_len > 200) {
        try stdout.print("Public key (first 200 bytes): {x} Length: {d}\n\n", .{ pk[0..200], pk_len });
    } else try stdout.print("Private key: {x} Length: {d}\n\n", .{ pk, pk_len });

    if (ct.len > 200) {
        try stdout.print("Ciphertext (first 200 bytes): {x} Length: {d}\n\n", .{ ct[0..200], ct.len });
    } else try stdout.print("Ciphertext: {x} Length: {d}\n\n", .{ ct, ct.len });

    try stdout.print("Sender shared secret: {x} Length: {d}\n\n", .{ ss_sender, ss_len });
    try stdout.print("Receiver shared secret: {x} Length: {d}\n\n", .{ ss_receiver, ss_len });

    if (match == true) try stdout.print("Match between sender and receiver\n\n", .{});

    try stdout.flush();
}
