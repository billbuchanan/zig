const std = @import("std");
const crypto = std.crypto;

pub fn main() !void {
    _ = crypto.core.Ascon(std.builtin.Endian.little);

    // The Ascon state can be stored as five 64-bit words. In Version 1.2, these were were in big-endian format, but Version 1.3 (NIST SP 800-232) uses little-endian representation.

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    // Get the command-line arguments

    var m: []u8 = undefined;

    var ad: []u8 = undefined;

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    // Check if there are any arguments
    if (args.len > 1) {
        m = args[1];
    }
    if (args.len > 2) {
        ad = args[2];
    }

    var key128: [crypto.ascon.AsconAead128.key_length]u8 = undefined;
    std.crypto.random.bytes(&key128);

    var nonce128: [16]u8 = undefined;
    std.crypto.random.bytes(&nonce128);

    const ciphertext128 = try allocator.alloc(u8, m.len);
    defer allocator.free(ciphertext128);

    const m2 = try allocator.alloc(u8, m.len);
    defer allocator.free(m2);

    var tag128: [crypto.ascon.AsconAead128.tag_length]u8 = undefined;

    crypto.ascon.AsconAead128.encrypt(ciphertext128, &tag128, m, ad, nonce128, key128);

    const ct1 = ciphertext128;

    try crypto.ascon.AsconAead128.decrypt(m2, ct1, tag128, ad, nonce128, key128);

    try stdout.print("== Ascon (128-bit)\n", .{});
    try stdout.print("\nMessage: {s}\n", .{m});
    try stdout.print("\nKey:\t{x} \n", .{key128});
    try stdout.print("Nonce:\t{x} \n", .{nonce128});
    try stdout.print("AD:\t{s} \n", .{ad});

    try stdout.print("\nCiphertext: {x} \n", .{ciphertext128});
    try stdout.print("  Tag:\t{x} \n", .{tag128});

    try stdout.print("\nDecrypted: {s} \n", .{m2});

    try stdout.flush();
}
