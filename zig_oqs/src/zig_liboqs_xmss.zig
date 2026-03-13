const std = @import("std");

const c = @cImport({
    @cInclude("oqs/oqs.h");
    @cInclude("oqs/sig_stfl.h");
});

var gpa1 = std.heap.GeneralPurposeAllocator(.{}){};
var stored_sk: ?[]u8 = null;

fn oqsOk(status: c.OQS_STATUS, what: []const u8) !void {
    if (status == c.OQS_SUCCESS) return;
    std.debug.print("{s} failed\n", .{what});

    return error.OqsError;
}

fn lock_cb(mutex: ?*anyopaque) callconv(.c) c.OQS_STATUS {
    _ = mutex;
    return c.OQS_SUCCESS;
}

fn unlock_cb(mutex: ?*anyopaque) callconv(.c) c.OQS_STATUS {
    _ = mutex;
    return c.OQS_SUCCESS;
}

fn store_cb(sk_buf: [*c]u8, sk_buf_len: usize, context: ?*anyopaque) callconv(.c) c.OQS_STATUS {
    _ = context;
    const allocator = gpa1.allocator();

    if (stored_sk) |old| allocator.free(old);

    const copy = allocator.alloc(u8, sk_buf_len) catch return c.OQS_ERROR;
    @memcpy(copy, sk_buf[0..sk_buf_len]);
    stored_sk = copy;
    return c.OQS_SUCCESS;
}

pub fn main() !void {
    defer {
        if (stored_sk) |buf| gpa1.allocator().free(buf);
        _ = gpa1.deinit();
    }

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const msg: []const u8 = args[1];
    const alg_name: []const u8 = args[2];

    // MUST be NUL-terminated
    const alg_z = try std.fmt.allocPrint(allocator, "{s}", .{alg_name});
    defer allocator.free(alg_z);

    if (c.OQS_SIG_STFL_alg_is_enabled(alg_z.ptr) != 1) {
        try stdout.print("XMSS algorithm not enabled in this liboqs build: {s}\n", .{alg_name});
        return error.AlgorithmUnavailable;
    }

    const sig = c.OQS_SIG_STFL_new(alg_z.ptr);
    if (sig == null) {
        try stdout.print("OQS_SIG_STFL_new failed for: {s}\n", .{alg_name});
        return error.AlgorithmUnavailable;
    }
    defer c.OQS_SIG_STFL_free(sig);

    const sk = c.OQS_SIG_STFL_SECRET_KEY_new(alg_z.ptr);
    if (sk == null) {
        try stdout.print("OQS_SIG_STFL_SECRET_KEY_new failed for: {s}\n", .{alg_name});
        return error.OutOfMemory;
    }
    defer c.OQS_SIG_STFL_SECRET_KEY_free(sk);

    c.OQS_SIG_STFL_SECRET_KEY_SET_mutex(sk, null);
    c.OQS_SIG_STFL_SECRET_KEY_SET_lock(sk, lock_cb);
    c.OQS_SIG_STFL_SECRET_KEY_SET_unlock(sk, unlock_cb);
    c.OQS_SIG_STFL_SECRET_KEY_SET_store_cb(sk, store_cb, null);

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

    var sk_buf_ptr: [*c]u8 = null;
    var sk_buf_len: usize = 0;

    try oqsOk(
        c.OQS_SIG_STFL_SECRET_KEY_serialize(&sk_buf_ptr, &sk_buf_len, sk),
        "OQS_SIG_STFL_SECRET_KEY_serialize",
    );
    defer c.OQS_MEM_secure_free(sk_buf_ptr, sk_buf_len);

    const sk_preview_len: usize = @min(sk_buf_len, 100);
    const sig_preview_len: usize = @min(signature_len, 100);

    try stdout.print("Algorithm: {s}\n", .{alg_name});
    try stdout.print("Message:   {s}\n", .{msg});
    try stdout.flush();

    try stdout.print("Private key (first {d} bytes): {x} Length: {d}\n\n", .{
        sk_preview_len,
        sk_buf_ptr[0..sk_preview_len],
        sk_buf_len,
    });

    try stdout.print("Public key: {x} Length: {d}\n\n", .{
        public_key[0..sig.*.length_public_key],
        sig.*.length_public_key,
    });

    try stdout.print("Signature (first {d} bytes): {x} Length: {d}\n\n", .{
        sig_preview_len,
        signature[0..sig_preview_len],
        signature_len,
    });

    try stdout.flush();
}
