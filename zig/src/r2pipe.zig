const std = @import("std");
const fmt = std.fmt; // @import("std.fmt");
const print = @import("std").debug.print;
const testing = std.testing;

extern fn read(fd: i32, ptr: *[4096]u8, len: i32) i32;
extern fn write(fd: i32, ptr: *const u8, len: i32) i32;

pub const R2PipeMode = enum {
    env,
    // http,
    api,
};

pub const R2Pipe = struct {
    fd_in: i32 = -1,
    fd_out: i32 = -1,
    allocator: *const std.mem.Allocator,

    pub fn init() R2Pipe {
        return R2Pipe{ .allocator = &std.heap.page_allocator };
    }

    //pub fn deinit(r2: *R2Pipe) void {
    // r2.arena.deinit();
    //}
    pub fn cmd(r2: R2Pipe, s: []const u8) ![]const u8 {
        var foo: [4096]u8 = [_]u8{0} ** 4096;
        if (r2.fd_in != -1 and r2.fd_out != -1) {
            _ = write(r2.fd_out, @ptrCast(*const u8, &s[0]), @intCast(i32, s.len));
            _ = write(r2.fd_out, @ptrCast(*const u8, "\n"), 1);
            const res = read(r2.fd_in, &foo, foo.len);
            if (res > 0) {
                var p = try r2.allocator.alloc(u8, @intCast(usize, 4096 + res + 1));
                std.mem.copy(u8, p, &foo);
                p = try r2.allocator.realloc(p, @intCast(usize, res + 1));
                var ss: []const u8 = p;
                return ss;
            }
            return "";
        }
        return "";
    }

    pub fn quit(r2: R2Pipe) void {
        _ = r2.cmd("q!!");
    }
};

pub fn open(file: []const u8) !R2Pipe {
    var r2 = R2Pipe.init();
    if (std.mem.eql(u8, file, "")) {
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();

        const env_map = try arena.allocator().create(std.process.EnvMap);
        env_map.* = try std.process.getEnvMap(arena.allocator());
        defer env_map.deinit();

        const sin = env_map.get("R2PIPE_IN") orelse "";
        const sout = env_map.get("R2PIPE_OUT") orelse "";
        var fail = false;
        if (std.mem.eql(u8, sin, "")) {
            fail = true;
        }
        if (std.mem.eql(u8, sout, "")) {
            fail = true;
        }
        const iin = try std.fmt.parseInt(i32, sin, 0);
        const iout = try std.fmt.parseInt(i32, sout, 0);
        // print("in:{d} out:{d}\n", .{ iin, iout });
        r2.fd_in = iin;
        r2.fd_out = iout;
    }
    // _ = r2.cmd("o /bin/ls");
    _ = file;
    //    print("{s}", @TypeOf(r2));
    return r2;
}

/// deprecated
// pub export uses C semantics
pub export fn add(a: i32, b: i32) i32 {
    return a + b;
}
test "basic add functionality" {
    try testing.expect(add(3, 7) == 10);
}
