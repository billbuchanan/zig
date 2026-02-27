const std = @import("std");
const aead = @import("std").crypto.aead;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var stdout_buffer: [4096]u8 = undefined;
    var stdout = std.fs.File.stdout().writer(&stdout_buffer);

    // Get the command-line arguments

    var m: []const u8 = undefined;

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    // Check if there are any arguments
    if (args.len > 1) {
        m = args[1];
    }

    var key: [aead.aes_gcm_siv.Aes128GcmSiv.key_length]u8 = undefined;
    std.crypto.random.bytes(&key);
    var nonce: [aead.aes_gcm_siv.Aes128GcmSiv.nonce_length]u8 = undefined;
    std.crypto.random.bytes(&nonce);

    const ad = "Add";

    const ciphertext = try allocator.alloc(u8, m.len);
    defer allocator.free(ciphertext);

    var tag: [aead.aes_gcm_siv.Aes128GcmSiv.tag_length]u8 = undefined;

    aead.aes_gcm_siv.Aes128GcmSiv.encrypt(ciphertext, &tag, m, ad, nonce, key);

    const m2 = try allocator.alloc(u8, m.len);
    defer allocator.free(m2);

    const ct = ciphertext;
    try aead.aes_gcm_siv.Aes128GcmSiv.decrypt(m2, ct, tag, ad, nonce, key);

    try stdout.interface.print("AES-GCM-SIV (128-bit)\n", .{});
    try stdout.interface.print("\nMessage: {s}\n", .{m});
    try stdout.interface.print("\nKey:\t{x} \n", .{key});
    try stdout.interface.print("Nonce:\t{x} \n", .{nonce});
    try stdout.interface.print("AD:\t{s} \n", .{ad});

    try stdout.interface.print("\nCiphertext: {x} \n", .{ciphertext});
    try stdout.interface.print("  Tag:\t{x} \n", .{tag});

    try stdout.interface.print("\nDecrypted: {s} \n", .{m2});
    try stdout.interface.flush();
}
