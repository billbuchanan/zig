const std = @import("std");
const crypto = @import("std").crypto;

pub fn main() !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    // create a seed for the encapsulation
    var seed: [32]u8 = undefined;
    crypto.random.bytes(&seed);

    const kp = crypto.kem.ml_kem.MLKem1024.KeyPair.generate();

    const ct = crypto.kem.ml_kem.MLKem1024.PublicKey.encaps(kp.public_key, seed);

    const sharedkey = try crypto.kem.ml_kem.MLKem1024.SecretKey.decaps(kp.secret_key, &ct.ciphertext);

    // Derive a 32-byte (256-bit) key with HKDF-Sha256
    var derived_key: [32]u8 = undefined;
    crypto.kdf.hkdf.HkdfSha256.expand(&derived_key, "context", sharedkey);

    try stdout.print("ML-KEM-1024\n", .{});

    try stdout.print("\nAlice secret key (truncated to 128 bytes):\t{x} Length: {d}\n", .{ kp.secret_key.toBytes()[0..256], kp.secret_key.toBytes().len });
    try stdout.print("\nAlice public key (truncated to 128 bytes):\t{x} Length: {d}\n", .{ kp.public_key.toBytes()[0..256], kp.public_key.toBytes().len });
    try stdout.print("\nBob sends ciphertext (truncated to 128 bytes):\t{x} Length {d}\n", .{ ct.ciphertext[0..256], ct.ciphertext.len });
    try stdout.print("\nBob's secret:\t{x}\n", .{ct.shared_secret});
    try stdout.print("\nAlice decapsulates:\t{x}\n", .{sharedkey});

    try stdout.print("\nDerived shared 256-bit key (HKDF-SHA256): {x}\n", .{derived_key});

    try stdout.flush();
}
