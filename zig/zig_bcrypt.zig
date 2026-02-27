const std = @import("std");
const pwhash = @import("std").crypto.pwhash;

pub fn main() !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    // Get the command-line arguments

    var password: []const u8 = undefined;
    var rounds: []const u8 = undefined;

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    // Check if there are any arguments
    if (args.len > 1) {
        password = args[1];
    }
    if (args.len > 2) {
        rounds = args[2];
    }

    const r = try std.fmt.parseInt(u6, rounds, 10);

    var key: [72]u8 = undefined;

    const hash_options = pwhash.bcrypt.HashOptions{
        .params = .{ .rounds_log = r, .silently_truncate_password = false },
        .encoding = .crypt,
    };

    const res = try pwhash.bcrypt.strHash(password, hash_options, &key);

    try stdout.print("== bcrypt\n", .{});
    try stdout.print("Password:\t{s}\n", .{password});
    try stdout.print("Log(rounds):\t{s}\n", .{rounds});
    try stdout.print("bcrypt:\t\t{s}\n", .{res});

    const verify_options = pwhash.bcrypt.VerifyOptions{ .silently_truncate_password = false };

    var rtn = pwhash.bcrypt.strVerify(res, password, verify_options);

    if (rtn != error.AuthenticationFailed)
        try stdout.print("bcrypt has been verified\n", .{});

    rtn = pwhash.bcrypt.strVerify(res, "Fake!", verify_options);

    if (rtn != error.AuthenticationFailed)
        try stdout.print("bcrypt has been not verified for incorrect password", .{});

    try stdout.flush();
}
