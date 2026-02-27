const std = @import("std");
const crypto = std.crypto;
const aead = @import("std").crypto.aead;

pub fn xorSlices(
    out: []u8,
    a: []const u8,
    b: []const u8,
) !void {
    if (a.len != b.len or out.len != a.len)
        return error.LengthMismatch;

    for (out, a, b) |*o, x, y| {
        o.* = x ^ y;
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    // Get the command-line arguments

    var Alice_Password: []const u8 = undefined;
    var Bob_Password: []const u8 = undefined;

    var m: []u8 = undefined;

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    // Check if there are any arguments
    if (args.len > 1) {
        m = args[1];
    }
    if (args.len > 2) {
        Bob_Password = args[2];
    }
    if (args.len > 3) {
        Alice_Password = args[3];
    }

    const Bob_Key = try allocator.alloc(u8, m.len);
    defer allocator.free(Bob_Key);
    const Alice_Key = try allocator.alloc(u8, m.len);
    defer allocator.free(Alice_Key);
    const ct = try allocator.alloc(u8, m.len);
    defer allocator.free(ct);
    const m2 = try allocator.alloc(u8, m.len);
    defer allocator.free(m2);
    const Bob_nonce = try allocator.alloc(u8, m.len);
    defer allocator.free(Bob_nonce);
    std.crypto.random.bytes(Bob_nonce);
    const Alice_nonce = try allocator.alloc(u8, m.len);
    defer allocator.free(Alice_nonce);
    std.crypto.random.bytes(Alice_nonce);

    crypto.hash.sha3.Shake128.hash(Alice_Password, Alice_Key, .{});
    crypto.hash.sha3.Shake128.hash(Bob_Password, Bob_Key, .{});

    try xorSlices(ct, m, Bob_Key);
    try xorSlices(ct, ct, Bob_nonce);
    try xorSlices(ct, ct, Alice_Key);
    try xorSlices(ct, ct, Alice_nonce);
    const ciphertext = ct;
    try xorSlices(ct, ct, Bob_Key);
    try xorSlices(ct, ct, Bob_nonce);
    try xorSlices(ct, ct, Alice_Key);
    try xorSlices(m2, ct, Alice_nonce);

    try stdout.print("SHAKE128 Commutative Encryption\n", .{});
    try stdout.print("Encrypt with Bob's key, then Alice's, and then decrypt with Bob's key and then Alice's\n", .{});
    try stdout.print("\nMessage:\t{s}\n", .{m});
    try stdout.print("\nBob password:\t{s} \n", .{Bob_Password});
    try stdout.print("Bob Key:\t{x} \n", .{Bob_Key});
    try stdout.print("   Bob Nonce:\t{x} \n", .{Bob_nonce});

    try stdout.print("\nAlice password:\t{s} \n", .{Alice_Password});
    try stdout.print("Alice Key:\t{x} \n", .{Alice_Key});
    try stdout.print("   Alice Nonce:\t{x} \n", .{Alice_nonce});

    try stdout.print("\nCiphertext:\t{x} \n", .{ciphertext});

    try stdout.print("\nDecrypted:\t{s} \n", .{m2});
    try stdout.flush();
}
