const std = @import("std");
const print = @import("std").debug.print;
const r2pipe = @import("src/r2pipe.zig");

pub fn main() !void {
    try inr2();
}

fn inr2() !void {
    const r2 = try r2pipe.open("");
    const res = r2.cmd("?E Hello World");
    print("Hello, {s}!\n{s}\n", .{ "world", res });
}

fn inspawn() !void {
    const r2 = try r2pipe.open("/bin/ls");
    const res = r2.cmd("?E Hello World");
    print("Hello, {s}!\n{s}\n", .{ "world", res });
    r2.quit();
}
