const std = @import("std");
const Camellia128 = @import("camellia").Camellia128;


pub fn main() !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    const m: [16]u8 = .{ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const m2: [16]u8 = undefined;

    var key: [16]u8 = undefined;
    std.crypto.random.bytes(&key);

    var context = Camellia128.initEncrypt(key);
    var output: [16]u8 = undefined;
    context.encrypt(&output, &m);

    var context2 = Camellia128.initDecrypt(key);
    var output2: [16]u8 = undefined;
    context2.decrypt(&output2, &m2);

    try stdout.print("Hashing: {s}\n", .{m});
    try stdout.print("Hashing: {s}\n", .{m2});
    try stdout.flush();
}
