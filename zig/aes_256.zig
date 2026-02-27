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

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    // Check if there are any arguments
    if (args.len > 1) {
        m = args[1];
    }

    var key: [aead.aes_gcm.Aes256Gcm.key_length]u8 = undefined;
    std.crypto.random.bytes(&key);
    var nonce: [aead.aes_gcm.Aes256Gcm.nonce_length]u8 = undefined;
    std.crypto.random.bytes(&nonce);

    const ad = "Add";

    const ciphertext = try allocator.alloc(u8, m.len);
    defer allocator.free(ciphertext);

    var tag: [aead.aes_gcm.Aes128Gcm.tag_length]u8 = undefined;

    aead.aes_gcm.Aes256Gcm.encrypt(ciphertext, &tag, m, ad, nonce, key);

    const m2 = try allocator.alloc(u8, m.len);
    defer allocator.free(m2);

    const ct = ciphertext;
    try aead.aes_gcm.Aes256Gcm.decrypt(m2, ct, tag, ad, nonce, key);

    try stdout.print("AE.S-GCM (256-bit)\n", .{});
    try stdout.print("\nMessage: {s}\n", .{m});
    try stdout.print("\nKey:\t{x} \n", .{key});
    try stdout.print("Nonce:\t{x} \n", .{nonce});
    try stdout.print("AD:\t{s} \n", .{ad});

    try stdout.print("\nCiphertext: {x} \n", .{ciphertext});
    try stdout.print("  Tag:\t{x} \n", .{tag});

    try stdout.print("\nDecrypted: {s} \n", .{m2});
    try stdout.flush();
}
