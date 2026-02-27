const std = @import("std");
const pwhash = @import("std").crypto.pwhash;

pub fn main() !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    // Get the command-line arguments

    var password: []const u8 = undefined;
    var rounds: []const u8 = undefined;
    var salt: []const u8 = undefined;

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    // Check if there are any arguments
    if (args.len > 1) {
        password = args[1];
    }
    if (args.len > 2) {
        salt = args[2];
    }
    if (args.len > 3) {
        rounds = args[3];
    }

    const r = try std.fmt.parseInt(u6, rounds, 10);
    const r2 = try std.fmt.parseInt(u32, rounds, 10);

    var saltb: [16]u8 = undefined;
    std.crypto.random.bytes(&saltb);
    var key: [72]u8 = undefined; // 256-bit key

    const hash_options = pwhash.bcrypt.HashOptions{
        .params = .{ .rounds_log = r, .silently_truncate_password = false },
        .encoding = .crypt,
    };

    const res = try pwhash.bcrypt.strHash(password, hash_options, &key);

    try stdout.print("== bcrypt\n", .{});
    try stdout.print("Password:\t{s}\n", .{password});
    try stdout.print("Salt:\t\t{x}\n", .{saltb});

    try stdout.print("bcrypt:\t\t{s}\n", .{res});

    var key2: [100]u8 = undefined; // 100 byte key
    _ = try pwhash.bcrypt.opensshKdf(password, salt, &key2, r2);

    try stdout.print("\nOpensshKdf:\n", .{});
    try stdout.print("Password:\t{s}\n", .{password});
    try stdout.print(" Salt:\t\t{s}\n", .{salt});
    try stdout.print(" Rounds:\t{d}\n", .{r2});
    try stdout.print(" Key:\t\t{x}\n", .{key2});

    _ = try pwhash.bcrypt.pbkdf(password, salt, &key, r2);

    try stdout.print("\nbcrypt-PBKDF2:\n", .{});
    try stdout.print("Password:\t{s}\n", .{password});
    try stdout.print(" Salt:\t\t{s}\n", .{salt});
    try stdout.print(" Rounds:\t{d}\n", .{r});
    try stdout.print(" Key:\t\t{x}\n", .{key});

    try stdout.flush();
}
