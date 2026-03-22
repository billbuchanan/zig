const std = @import("std");
const MerkleTree = @import("merkle.zig");
pub const HASH_SIZE = 32;

/// Merkle tree node hash type
pub const Hash = [HASH_SIZE]u8;

pub fn main() !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    var hash256_1: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    var hash256_2: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    var hash256_3: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    var hash256_4: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;

    std.crypto.hash.sha2.Sha256.hash(args[1], &hash256_1, .{});
    std.crypto.hash.sha2.Sha256.hash(args[2], &hash256_2, .{});
    std.crypto.hash.sha2.Sha256.hash(args[3], &hash256_3, .{});
    std.crypto.hash.sha2.Sha256.hash(args[4], &hash256_4, .{});

    const to_prove = try std.fmt.parseInt(usize, args[5], 10);

    const leaves = &[_]Hash{
        hash256_1,
        hash256_2,
        hash256_3,
        hash256_4,
    };

    const allocator = std.heap.page_allocator;

    var tree = try MerkleTree.MerkleTree.build(allocator, leaves);
    defer tree.deinit();
    const root = tree.root();

    const proof = try tree.generateProof(to_prove);
    defer allocator.free(proof);

    const valid = tree.verifyProof(leaves[to_prove], to_prove, proof);

    try stdout.print("\nData: {s}, {s}, {s}, {s}\n", .{ args[1], args[2], args[3], args[4] });
    try stdout.print("\nLeaf 1 (SHA-256): {x}\n", .{hash256_1});
    try stdout.print("Leaf 2 (SHA-256): {x}\n", .{hash256_2});
    try stdout.print("Leaf 3 (SHA-256): {x}\n", .{hash256_3});
    try stdout.print("Leaf 4 (SHA-256): {x}\n", .{hash256_4});

    try stdout.print("\nMerkle Root {x}\n", .{root});

    try stdout.print("\nProof for {s}: \n", .{args[to_prove + 1]});
    for (0..proof.len) |i| {
        try stdout.print(" {x}\n", .{proof[i]});
    }
    if (valid) {
        try stdout.print("\nLeaf has been proven\n", .{});
    }

    try stdout.flush();
}
