const std = @import("std");
const crypto = @import("std").crypto;
const allocator = std.heap.page_allocator;

pub fn main() !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    // Get the command-line arguments

    var password: []u8 = undefined;

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    // Check if there are any arguments
    if (args.len > 1) {
        password = args[1];
    }

    try stdout.print("Password: {s}\n", .{password});

    var output_buf: [200]u8 = undefined;
    var params = crypto.pwhash.argon2.Params.owasp_2id;
    var hash_options = crypto.pwhash.argon2.HashOptions{
        .allocator = allocator,
        .params = params,
        .mode = .argon2id,
    };

    var hash_str = try crypto.pwhash.argon2.strHash(password, hash_options, &output_buf);
    try stdout.print("Hash string (Argon2id): {s}\n", .{hash_str}); // Store this string

    // Verification process
    const stored_hash_str = hash_str; // Retrieve stored hash string
    const verify_options = crypto.pwhash.argon2.VerifyOptions{ .allocator = allocator };
    try crypto.pwhash.argon2.strVerify(stored_hash_str, password, verify_options);

    try stdout.print("\nPassword verified\n", .{});

    // Now try Argon2i
    params.t = 1;
    params.m = 4 * 1024;
    params.p = 1;

    hash_options = crypto.pwhash.argon2.HashOptions{
        .allocator = allocator,
        .params = params,
        .mode = .argon2i,
    };
    hash_str = try crypto.pwhash.argon2.strHash(password, hash_options, &output_buf);
    try stdout.print("\nHash string (Argon2i): {s}\n", .{hash_str}); // Store this string

    try stdout.flush();
}
