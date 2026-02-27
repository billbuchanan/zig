const std = @import("std");
const aead = @import("std").crypto.aead;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    // Get the command-line arguments

    var m: []const u8 = undefined;
    var ad: []const u8 = undefined;

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    // Check if there are any arguments
    if (args.len > 1) {
        m = args[1];
    }
    if (args.len > 2) {
        ad = args[2];
    }

    var key128: [aead.aegis.Aegis128L.key_length]u8 = undefined;
    std.crypto.random.bytes(&key128);
    var nonce128: [aead.aegis.Aegis128L.nonce_length]u8 = undefined;
    std.crypto.random.bytes(&nonce128);

    var key256: [aead.aegis.Aegis256.key_length]u8 = undefined;
    std.crypto.random.bytes(&key256);
    var nonce256: [aead.aegis.Aegis256.nonce_length]u8 = undefined;
    std.crypto.random.bytes(&nonce256);

    const ciphertext128 = try allocator.alloc(u8, m.len);
    defer allocator.free(ciphertext128);
    const ciphertext256 = try allocator.alloc(u8, m.len);
    defer allocator.free(ciphertext256);

    var tag128: [aead.aegis.Aegis128L.tag_length]u8 = undefined;
    var tag256: [aead.aegis.Aegis256.tag_length]u8 = undefined;

    aead.aegis.Aegis128L.encrypt(ciphertext128, &tag128, m, ad, nonce128, key128);
    aead.aegis.Aegis256.encrypt(ciphertext256, &tag256, m, ad, nonce256, key256);

    const m2 = try allocator.alloc(u8, m.len);
    defer allocator.free(m2);
    const m3 = try allocator.alloc(u8, m.len);
    defer allocator.free(m3);

    const ct1 = ciphertext128;
    const ct2 = ciphertext256;
    try aead.aegis.Aegis128L.decrypt(m2, ct1, tag128, ad, nonce128, key128);
    try aead.aegis.Aegis256.decrypt(m3, ct2, tag256, ad, nonce256, key256);

    try stdout.print("== Aegis128L (128-bit)\n", .{});
    try stdout.print("\nMessage: {s}\n", .{m});
    try stdout.print("\nKey:\t{x} \n", .{key128});
    try stdout.print("Nonce:\t{x} \n", .{nonce128});
    try stdout.print("AD:\t{s} \n", .{ad});

    try stdout.print("\nCiphertext: {x} \n", .{ciphertext128});
    try stdout.print("  Tag:\t{x} \n", .{tag128});

    try stdout.print("\nDecrypted: {s} \n", .{m2});

    try stdout.print("\n\n== Aegis256 (256-bit)\n", .{});
    try stdout.print("\nMessage: {s}\n", .{m});
    try stdout.print("\nKey:\t{x} \n", .{key256});
    try stdout.print("Nonce:\t{x} \n", .{nonce256});
    try stdout.print("AD:\t{s} \n", .{ad});

    try stdout.print("\nCiphertext: {x} \n", .{ciphertext256});
    try stdout.print("  Tag:\t{x} \n", .{tag256});

    try stdout.print("\nDecrypted: {s} \n", .{m3});
    try stdout.flush();
}
