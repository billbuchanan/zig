const std = @import("std");
const crypto = @import("std").crypto;
const X25519 = crypto.dh.X25519;

pub fn main() !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    try stdout.print("== X25519 Key Exchange ==\n\n", .{});

    // Alice generates keys
    const alice_key_pair = X25519.KeyPair.generate();

    // Bob generates keys
    const bob_key_pair = X25519.KeyPair.generate();

    // Bob and Alice exchange public keys

    // Alice gets shared secret
    const alice_shared_secret = try X25519.scalarmult(alice_key_pair.secret_key, bob_key_pair.public_key);

    // Bob gets shared secret
    const bob_shared_secret = try X25519.scalarmult(bob_key_pair.secret_key, alice_key_pair.public_key);

    // Check secrets are identical
    std.debug.assert(std.mem.eql(u8, &alice_shared_secret, &bob_shared_secret));

    // Derive a 256-bit key with HKDF-SHA-256 (we can also use HKDF-SHA-512)
    var derived_key: [32]u8 = undefined;
    const prk = crypto.kdf.hkdf.HkdfSha256.extract("Salty", alice_shared_secret[0..32]);
    crypto.kdf.hkdf.HkdfSha256.expand(&derived_key, "content", prk);

    try stdout.print("Alice's secret key: {x}\n", .{alice_key_pair.secret_key});
    try stdout.print("Alice's public key: {x}\n", .{alice_key_pair.public_key});

    try stdout.print("\nBob's secret key: {x}\n", .{bob_key_pair.secret_key});
    try stdout.print("Bob's public key: {x}\n", .{bob_key_pair.public_key});

    try stdout.print("\nAlice's shared secret: {x}\n", .{alice_shared_secret});
    try stdout.print("Bob's shared secret: {x}\n", .{bob_shared_secret});

    try stdout.print("\nDerived shared key (HKDF): {x}\n", .{derived_key});

    try stdout.flush();
}
