const std = @import("std");
const crypto = @import("std").crypto;
const aead = @import("std").crypto.aead;

pub fn main() !void {
    var message: []u8 = undefined;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);
    // Check if there are any arguments
    if (args.len > 1) {
        message = args[1];
    }

    // create a seed for the encapsulation
    var seed: [32]u8 = undefined;
    crypto.random.bytes(&seed);

    const kp = crypto.kem.ml_kem.MLKem1024.KeyPair.generate();

    const ct = crypto.kem.ml_kem.MLKem1024.PublicKey.encaps(kp.public_key, seed);

    // Derive a 256-bit key with HKDF-Sha256
    var derived_key: [32]u8 = undefined;
    var prk = crypto.kdf.hkdf.HkdfSha256.extract("Salty", ct.shared_secret[0..32]);
    crypto.kdf.hkdf.HkdfSha256.expand(&derived_key, "content", prk);

    // Bob now encrypts the message with the secret ey

    var nonce: [aead.aes_gcm.Aes256Gcm.nonce_length]u8 = undefined;
    std.crypto.random.bytes(&nonce);

    const ad = "Add";

    const ciphertext = try allocator.alloc(u8, message.len);
    defer allocator.free(ciphertext);

    var tag: [aead.aes_gcm.Aes128Gcm.tag_length]u8 = undefined;

    aead.aes_gcm.Aes256Gcm.encrypt(ciphertext, &tag, message, ad, nonce, derived_key);

    // Alice decapsulates with her secret key

    const sharedkey = try crypto.kem.ml_kem.MLKem1024.SecretKey.decaps(kp.secret_key, &ct.ciphertext);

    var derived_key2: [32]u8 = undefined;
    prk = crypto.kdf.hkdf.HkdfSha256.extract("Salty", sharedkey[0..32]);
    crypto.kdf.hkdf.HkdfSha256.expand(&derived_key2, "content", prk);

    const m2 = try allocator.alloc(u8, message.len);
    defer allocator.free(m2);

    try aead.aes_gcm.Aes256Gcm.decrypt(m2, ciphertext, tag, ad, nonce, derived_key2);

    try stdout.print("Hybrid ML-KEM-1024 Encryption\n", .{});
    try stdout.print("Message: {s}\n", .{message});
    try stdout.print("\nAlice secret key (truncated to 64 bytes):\t{x} Length: {d}\n", .{ kp.secret_key.toBytes()[0..128], kp.secret_key.toBytes().len });
    try stdout.print("\nAlice public key (truncated to 64 bytes):\t{x} Length: {d}\n", .{ kp.public_key.toBytes()[0..128], kp.public_key.toBytes().len });
    try stdout.print("\nBob sends ciphertext (truncated to 64 bytes):\t{x} Length {d}\n", .{ ct.ciphertext[0..256], ct.ciphertext.len });
    try stdout.print("\nBob's secret:\t{x}\n", .{ct.shared_secret});
    try stdout.print("\nBob's cipher to Alice:\t{x}\n", .{ciphertext});
    try stdout.print("\nAlice decapsulates:\t{x}\n", .{sharedkey});

    try stdout.print("\nBob shared 256-bit key (HKDF-SHA256): {x}\n", .{derived_key});
    try stdout.print("Alice shared 256-bit key (HKDF-SHA256): {x}\n", .{derived_key2});
    try stdout.print("\nDecrypted: {s}\n", .{m2});

    try stdout.flush();
}
