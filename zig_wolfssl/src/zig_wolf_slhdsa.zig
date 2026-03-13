const std = @import("std");

const c = @cImport({
    @cInclude("oqs/oqs.h");
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

    const msg: []const u8 = args[1];
    const alg_name: []const u8 = args[2];

    // Method name
    const alg_z = try std.fmt.allocPrint(allocator, "{s}", .{alg_name});
    defer allocator.free(alg_z);

    const sig = c.OQS_SIG_new(alg_z.ptr);
    defer c.OQS_SIG_free(sig);

    const pub_len: usize = sig.*.length_public_key;
    const sec_len: usize = sig.*.length_secret_key;
    const sig_max_len: usize = sig.*.length_signature;

    const public_key = try allocator.alloc(u8, pub_len);
    defer allocator.free(public_key);

    const secret_key = try allocator.alloc(u8, sec_len);
    defer allocator.free(secret_key);

    const signature = try allocator.alloc(u8, sig_max_len);
    defer allocator.free(signature);

    var signature_len: usize = 0;

    try oqsOk(
        c.OQS_SIG_keypair(sig, public_key.ptr, secret_key.ptr),
        "OQS_SIG_keypair",
    );

    try oqsOk(
        c.OQS_SIG_sign(
            sig,
            signature.ptr,
            &signature_len,
            msg.ptr,
            msg.len,
            secret_key.ptr,
        ),
        "OQS Sign",
    );

    const rtn = c.OQS_SIG_verify(sig, msg.ptr, msg.len, signature.ptr, signature_len, public_key.ptr);

    try out.print("Algorithm: {s}\n", .{alg_name});
    try out.print("Message:   {s}\n\n", .{msg});

    try out.print("Public key:\t{x} Length: {d}\n\n", .{ public_key, pub_len });
    try out.print("Secret key:\t{x} Length: {d}\n\n", .{ secret_key, sec_len });
    try out.print("Signature (first 100 bytes):\t{x} Length: {d}\n\n", .{ signature[0..100], signature_len });

    if (rtn == c.OQS_SUCCESS) try out.print("Signature verified\n", .{});

    try out.flush();
}
