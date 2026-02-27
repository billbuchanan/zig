const std = @import("std");
const pwhash = @import("std").crypto.pwhash;

pub fn main() !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;
    // Get the command-line arguments

    var password: []const u8 = undefined;
    var salt: []const u8 = undefined;
    var rounds: []const u8 = undefined;

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

    const r = try std.fmt.parseInt(u32, rounds, 10);

    var HmacSha224: [32]u8 = undefined;
    var HmacSha256: [32]u8 = undefined;
    var HmacSha384: [32]u8 = undefined;
    var HmacSha512: [32]u8 = undefined;
    var HmacSha1: [32]u8 = undefined;

    try pwhash.pbkdf2(&HmacSha224, password, salt, r, std.crypto.auth.hmac.sha2.HmacSha224);
    try pwhash.pbkdf2(&HmacSha256, password, salt, r, std.crypto.auth.hmac.sha2.HmacSha256);
    try pwhash.pbkdf2(&HmacSha384, password, salt, r, std.crypto.auth.hmac.sha2.HmacSha384);
    try pwhash.pbkdf2(&HmacSha512, password, salt, r, std.crypto.auth.hmac.sha2.HmacSha512);
    try pwhash.pbkdf2(&HmacSha1, password, salt, r, std.crypto.auth.hmac.HmacSha1);

    try stdout.print("== PBKDF2\n", .{});
    try stdout.print("Password:\t{s}\n", .{password});
    try stdout.print("Salt:\t\t{s}\n", .{salt});
    try stdout.print("Rounds:\t\t{d}\n\n", .{r});
    try stdout.print("PBKDF2-HMAC-SHA224:\t{x}\n", .{HmacSha224});
    try stdout.print("PBKDF2-HMAC-SHA256:\t{x}\n", .{HmacSha256});
    try stdout.print("PBKDF2-HMAC-SHA384:\t{x}\n", .{HmacSha384});
    try stdout.print("PBKDF2-HMAC-SHA512:\t{x}\n", .{HmacSha512});
    try stdout.print("PBKDF2-HMAC-HmacSha1:\t{x}\n", .{HmacSha1});
    try stdout.flush();
}
