//! Merkle Tree

const std = @import("std");

const testing = std.testing;

/// Merkle Root is 32 bytes (128 bits)
pub const HASH_SIZE = 32;

/// Merkle Root Hash type
pub const Hash = [HASH_SIZE]u8;

/// A few Merkle tree errors
pub const MerkleError = error{
    EmptyLeaves,
    InvalidProof,
    InvalidLeafIndex,
    OutOfMemory,
};

// Stores Merkle tree
pub const MerkleTree = struct {
    allocator: std.mem.Allocator,
    leaves: []Hash,
    root_hash: Hash,

    /// Build Merkle tree from leaves
    pub fn build(allocator: std.mem.Allocator, leaves: []const Hash) !MerkleTree {
        if (leaves.len == 0) {
            return MerkleError.EmptyLeaves;
        }

        // Leaves copy
        const leaves_copy = try allocator.alloc(Hash, leaves.len);
        errdefer allocator.free(leaves_copy);
        @memcpy(leaves_copy, leaves);

        // Get the root
        const root_hash = try computeRoot(allocator, leaves);

        return MerkleTree{
            .allocator = allocator,
            .leaves = leaves_copy,
            .root_hash = root_hash,
        };
    }

    /// Free memory from tree
    pub fn deinit(self: *MerkleTree) void {
        self.allocator.free(self.leaves);
    }

    /// Reveal root
    pub fn root(self: *const MerkleTree) Hash {
        return self.root_hash;
    }

    /// Generate a Merkle proof for a specific leaf
    pub fn generateProof(
        self: *const MerkleTree,
        leaf_index: usize,
    ) ![]Hash {
        if (leaf_index >= self.leaves.len) {
            return MerkleError.InvalidLeafIndex;
        }

        var proof: std.ArrayList(Hash) = .empty;
        errdefer proof.deinit(self.allocator);

        // Build proof by walking up the tree
        var current_level = try self.allocator.alloc(Hash, self.leaves.len);
        defer self.allocator.free(current_level);
        @memcpy(current_level, self.leaves);

        var current_index = leaf_index;

        while (current_level.len > 1) {
            // Find sibling
            const sibling_index = if (current_index % 2 == 0)
                current_index + 1
            else
                current_index - 1;

            // Add sibling to proof if it exists
            if (sibling_index < current_level.len) {
                try proof.append(self.allocator, current_level[sibling_index]);
            } else {
                // Odd number of nodes, duplicate last node
                try proof.append(self.allocator, current_level[current_index]);
            }

            // Build next level
            const next_level_size = (current_level.len + 1) / 2;
            var next_level = try self.allocator.alloc(Hash, next_level_size);

            for (0..next_level_size) |i| {
                const left_idx = i * 2;
                const right_idx = left_idx + 1;

                const left = current_level[left_idx];
                const right = if (right_idx < current_level.len)
                    current_level[right_idx]
                else
                    current_level[left_idx]; // Duplicate if odd

                next_level[i] = hashPair(left, right);
            }

            self.allocator.free(current_level);
            current_level = next_level;
            current_index = current_index / 2;
        }

        return proof.toOwnedSlice(self.allocator);
    }

    /// Verify a Merkle proof

    pub fn verifyProof(
        self: *const MerkleTree,
        leaf_hash: Hash,
        leaf_index: usize,
        proof: []const Hash,
    ) bool {
        if (leaf_index >= self.leaves.len) {
            return false;
        }

        var computed_hash = leaf_hash;
        var current_index = leaf_index;

        // Reconstruct path to root
        for (proof) |sibling_hash| {
            computed_hash = if (current_index % 2 == 0)
                hashPair(computed_hash, sibling_hash)
            else
                hashPair(sibling_hash, computed_hash);

            current_index = current_index / 2;
        }

        // Check if computed root matches actual root
        return std.mem.eql(u8, &computed_hash, &self.root_hash);
    }
};

/// Compute Merkle root from leaves
fn computeRoot(allocator: std.mem.Allocator, leaves: []const Hash) !Hash {
    if (leaves.len == 0) {
        return error.EmptyLeaves;
    }

    if (leaves.len == 1) {
        return leaves[0];
    }

    var current_level = try allocator.alloc(Hash, leaves.len);
    defer allocator.free(current_level);
    @memcpy(current_level, leaves);

    while (current_level.len > 1) {
        const next_level_size = (current_level.len + 1) / 2;
        var next_level = try allocator.alloc(Hash, next_level_size);

        for (0..next_level_size) |i| {
            const left_idx = i * 2;
            const right_idx = left_idx + 1;

            const left = current_level[left_idx];
            const right = if (right_idx < current_level.len)
                current_level[right_idx]
            else
                current_level[left_idx]; // Duplicate if odd

            next_level[i] = hashPair(left, right);
        }

        allocator.free(current_level);
        current_level = next_level;
    }

    const root = current_level[0];
    return root;
}

/// Hash a pair of nodes to create parent node
///
/// Uses domain separation to prevent second-preimage attacks.
/// Internal nodes are hashed differently from leaves.
///
/// ## Parameters
/// - `left`: Left child hash
/// - `right`: Right child hash
///
/// ## Returns
/// Parent node hash
fn hashPair(left: Hash, right: Hash) Hash {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});

    hasher.update(&left);
    hasher.update(&right);

    var digest: [32]u8 = undefined;

    hasher.final(&digest);
    return (digest);
}
