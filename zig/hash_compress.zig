const std = @import("std");
const compress = std.compress;

pub fn main() !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    // Get the command-line arguments

    var data: []u8 = undefined;

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    // Check if there are any arguments
    if (args.len > 1) {
        data = args[1];
    }

    try stdout.print("Hashing: {s}\n", .{data});
    try stdout.flush();

    try stdout.print("\nFlate\n", .{});
    try stdout.flush();

    var out_buf: [16 * 1024]u8 = undefined;
    var out_writer = std.Io.Writer.fixed(&out_buf);

    try stdout.print("\nFlate\n", .{});
    try stdout.flush();

    const options: compress.flate.Compress.Options = .{
        .level = .default,
        .container = .zlib,
    };
    var flate_buf: [compress.flate.max_window_len]u8 = undefined;

    var comp = compress.flate.Compress.init(&out_writer, &flate_buf, options);

    try stdout.print("\nFlate 4\n", .{});
    try stdout.flush();

    try comp.writer.writeAll(data);
    try stdout.print("\nFlate 4\n", .{});
    try stdout.flush();
    try comp.writer.flush();

    const compressed = out_buf[0..out_writer.end];

    try stdout.print("\nCompressed {x}\n", .{compressed});

    try stdout.flush();
}
