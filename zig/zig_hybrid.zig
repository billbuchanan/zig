const std = @import("std");
const crypto = @import("std").crypto;

pub fn main() !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    // create a seed for key pair generation
    var seed: [32]u8 = undefined;
    crypto.random.bytes(&seed);

    // Fill with 80 bytes of randonmess for encapsulation
    var randomness: [80]u8 = undefined;
    crypto.random.bytes(&randomness);

    std.crypto.random.bytes(&randomness);

    const kp = try crypto.kem.hybrid.MlKem768P256.KeyPair.generateDeterministic(seed);

    const ct = try kp.public_key.encaps(&randomness);

    const bob_shared_secret = ct.shared_secret;

    const alice_shared_secret = try kp.secret_key.decaps(&ct.ciphertext);

    // Derive a 32-bit key with HKDF-Sha256
    var derived_key: [32]u8 = undefined;
    crypto.kdf.hkdf.HkdfSha256.expand(&derived_key, "context", alice_shared_secret);

    try stdout.print("MlKem768 with P256\n", .{});

    try stdout.print("\n\nAlice secret key (truncated to 128 bytes):\t{x} Length: {d}\n", .{ kp.secret_key.toBytes(), kp.secret_key.toBytes().len });
    try stdout.print("\nAlice public key (truncated to 128 bytes):\t{x} Length: {d}\n", .{ kp.public_key.toBytes()[0..256], kp.public_key.toBytes().len });
    try stdout.print("\nBob sends ciphertext (truncated to 128 bytes):\t{x} Length: {d}\n", .{ ct.ciphertext[0..256], ct.ciphertext.len });
    try stdout.print("\nBob's secret:\t{x}\n", .{bob_shared_secret});
    try stdout.print("\nAlice decapsulates:\t{x}\n", .{alice_shared_secret});
    try stdout.print("\nDerived shared 256-bit (32-byte) key (HKDF-SHA256): {x}\n", .{derived_key});
    try stdout.flush();
}
