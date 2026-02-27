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

    var key: [128]u8 = undefined;

    var hash_options: pwhash.scrypt.HashOptions = undefined;
    hash_options.allocator = std.heap.page_allocator;
    hash_options.params = .{ .ln = r, .r = 8, .p = 1 };
    //   hash_options.params = pwhash.scrypt.Params.fromLimits(1024, 8);
    hash_options.encoding = pwhash.Encoding.phc;

    // const hash_options: pwhash.scrypt.HashOptions = struct { allocator: alloc, params: pwhash.scrypt.Params.interactive, encoding: pwhash.Encoding };

    const res = try pwhash.scrypt.strHash(password, hash_options, &key);

    try stdout.print("== scrypt\n", .{});
    try stdout.print("Password:\t{s}\n", .{password});
    try stdout.print("CPU/Memory cost parameter (log2(N)):\t{s}\n", .{rounds});

    try stdout.print("scrypt:\t\t{s}\n", .{res});

    var verify_options: pwhash.scrypt.VerifyOptions = undefined;
    verify_options.allocator = std.heap.page_allocator;

    var rtn = pwhash.scrypt.strVerify(res, password, verify_options);

    if (rtn != error.AuthenticationFailed)
        try stdout.print("scrypt has been verified\n", .{});

    rtn = pwhash.scrypt.strVerify(res, "Fake!", verify_options);

    if (rtn != error.AuthenticationFailed)
        try stdout.print("scrypt has been not verified for incorrect password", .{});

    try stdout.flush();
}
