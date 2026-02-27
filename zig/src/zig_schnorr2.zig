const std = @import("std");
const crypto = @import("std").crypto;

pub fn main() !void {
    var message: []u8 = undefined;

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    // Check if there are any arguments
    if (args.len > 1) {
        message = args[1];
    }

    // Bob generates his private key (d) and public key (Q)
    const d = crypto.ecc.Edwards25519.scalar.Scalar.random();
    const Q = try crypto.ecc.Edwards25519.basePoint.mul(d.toBytes());

    //   k = curve.random_scalar()
    //   R = kG

    const k = crypto.ecc.Edwards25519.scalar.Scalar.random();
    const R = try crypto.ecc.Edwards25519.basePoint.mul(k.toBytes());

    // Compute c=H(R || Q || M)
    var e: [crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    var hasher = crypto.hash.sha2.Sha256.init(.{});
    hasher.update(R.toBytes()[0..32]);
    hasher.update(Q.toBytes()[0..32]);
    hasher.update(message);
    hasher.final(&e);

    // s = k + e.d
    const ed = crypto.ecc.Edwards25519.scalar.mul(e, d.toBytes());
    const s = crypto.ecc.Edwards25519.scalar.add(
        k.toBytes(),
        ed,
    );

    // Bob sends Alice (R,s). Now Bob uses Alice's public key (Q) to verify

    const sG = try crypto.ecc.Edwards25519.basePoint.mul(s);
    const eQ = try crypto.ecc.Edwards25519.mul(Q, e);
    const R_eQ = crypto.ecc.Edwards25519.add(R, eQ);

    try stdout.writeAll("Schnorr Signature with Edwards25519\n");
    try stdout.print("\nMessage= {s}\n", .{message});

    try stdout.print("\nBob's private d= {x}\n", .{d.toBytes()});
    try stdout.print("Bob's public Q= {x}\n", .{Q.toBytes()});
    try stdout.print("\nk= {x}\n", .{k.toBytes()});
    try stdout.print("\nR= {x}\n", .{R.toBytes()});
    try stdout.print("\ns= {x}\n", .{s});

    if (std.mem.eql(u8, sG.toBytes()[0..32], R_eQ.toBytes()[0..32])) {
        try stdout.writeAll("\nAlice has proven the signature\n");
    } else {
        try stdout.writeAll("\nAlice has NOT proven the signature\n");
    }

    try stdout.flush();
}
