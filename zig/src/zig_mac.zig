const std = @import("std");
const crypto = @import("std").crypto;

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

    try stdout.print("Message: {s}\n", .{data});

    var key256: [crypto.auth.hmac.sha2.HmacSha256.key_length]u8 = undefined;
    var key128: [16]u8 = undefined;

    // Fill 'key' with a secure random key
    crypto.random.bytes(&key256);
    crypto.random.bytes(&key128);

    var tagSha256: [crypto.auth.hmac.sha2.HmacSha256.mac_length]u8 = undefined;
    var tagSha1: [crypto.auth.hmac.HmacSha1.mac_length]u8 = undefined;
    var tagMd5: [crypto.auth.hmac.HmacMd5.mac_length]u8 = undefined;
    var tagPoly: [crypto.onetimeauth.Poly1305.mac_length]u8 = undefined;
    var tagPoly2: [crypto.onetimeauth.Polyval.mac_length]u8 = undefined;
    var tagGhash: [crypto.onetimeauth.Ghash.mac_length]u8 = undefined;

    var tagSip: [crypto.auth.siphash.SipHash128(4, 8).mac_length]u8 = undefined;
    var tagAegis: [crypto.auth.aegis.Aegis128LMac.mac_length]u8 = undefined;
    var tagCmac: [crypto.auth.cmac.CmacAes128.mac_length]u8 = undefined;

    crypto.auth.hmac.sha2.HmacSha256.create(&tagSha256, data, &key256);
    crypto.auth.hmac.HmacSha1.create(&tagSha1, data, &key256);
    crypto.auth.hmac.HmacMd5.create(&tagMd5, data, &key256);
    crypto.onetimeauth.Poly1305.create(&tagPoly, data, &key256);

    crypto.onetimeauth.Ghash.create(&tagGhash, data, &key128);
    crypto.auth.siphash.SipHash128(4, 8).create(&tagSip, data, &key128);
    crypto.onetimeauth.Polyval.create(&tagPoly2, data, &key128);
    crypto.auth.aegis.Aegis128LMac.create(&tagAegis, data, &key128);
    crypto.auth.cmac.CmacAes128.create(&tagCmac, data, &key128);

    try stdout.print("256-bit Key {x}\n", .{key256});
    try stdout.print(" HMAC (Sha256) {x}\n", .{tagSha256});
    try stdout.print(" HMAC (SHA1) {x}\n", .{tagSha1});
    try stdout.print(" HMAC (MD5) {x}\n", .{tagMd5});
    try stdout.print(" Poly1305 {x}\n", .{tagPoly});

    try stdout.print("\n128-bit Key {x}\n", .{key128});
    try stdout.print(" Siphash {x}\n", .{tagSip});
    try stdout.print(" Ghash {x}\n", .{tagGhash});
    try stdout.print(" Polyval {x}\n", .{tagPoly2});
    try stdout.print(" Aegis128 {x}\n", .{tagAegis});
    try stdout.print(" CMAC (AES-128) {x}\n", .{tagCmac});

    try stdout.flush();
}
