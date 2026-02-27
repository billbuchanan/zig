const std = @import("std");
const crypto = @import("std").crypto;

pub fn main() !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    var xstring: []u8 = undefined;
    var ystring: []u8 = undefined;
    var nstring: []u8 = undefined;

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    // Check if there are any arguments
    if (args.len > 1) {
        xstring = args[1];
    }
    if (args.len > 2) {
        ystring = args[2];
    }
    if (args.len > 3) {
        nstring = args[3];
    }
    const xval = try std.fmt.parseInt(u256, xstring, 10);
    const yval = try std.fmt.parseInt(u256, ystring, 10);
    const nval = try std.fmt.parseInt(u256, nstring, 10);

    const N = crypto.ff.Modulus(256);

    const n = try N.fromPrimitive(u256, nval);

    const x = try N.Fe.fromPrimitive(u256, n, xval);
    const y = try N.Fe.fromPrimitive(u256, n, yval);

    const res1 = n.add(x, y);
    const res2 = n.sub(x, y);
    const res3 = n.mul(x, y);
    const res4 = try n.pow(x, y);
    const res5 = n.sq(x);

    try stdout.print("Modulus: {s}\n\n", .{nstring});
    try stdout.print("{!}+{!} = {!}\n\n", .{ x.toPrimitive(u256), y.toPrimitive(u256), res1.toPrimitive(u256) });
    try stdout.print("{!}-{!} = {!}\n\n", .{ x.toPrimitive(u256), y.toPrimitive(u256), res2.toPrimitive(u256) });
    try stdout.print("{!}*{!} = {!}\n\n", .{ x.toPrimitive(u256), y.toPrimitive(u256), res3.toPrimitive(u256) });
    try stdout.print("{!}^{!} = {!}\n\n", .{ x.toPrimitive(u256), y.toPrimitive(u256), res4.toPrimitive(u256) });
    try stdout.print("{!}^2 = {!}\n\n", .{ x.toPrimitive(u256), res5.toPrimitive(u256) });

    try stdout.flush();
}
