const std = @import("std");
const fmt = std.fmt; // @import("std.fmt");
const print = @import("std").debug.print;
const testing = std.testing;

pub const R2PipeMode = enum {
    env,
    api,
    // http,
};

pub const R2Pipe = struct {
    fd_in: i32 = -1,
    fd_out: i32 = -1,
    allocator: *const std.mem.Allocator,

    pub fn init() R2Pipe {
        return R2Pipe{ .allocator = &std.heap.page_allocator };
    }

    pub fn deinit(r2: *R2Pipe) void {
        r2.arena.deinit();
    }
    pub fn cmd(r2: R2Pipe, s: []const u8) ![]const u8 {
        var foo: [4096]u8 = undefined;
        if (r2.fd_in != -1 and r2.fd_out != -1) {
            _ = try std.os.write(r2.fd_out, s);
            _ = try std.os.write(r2.fd_out, "\n");
            const res = try std.os.read(r2.fd_in, &foo);
            if (res > 0) {
                var p = try r2.allocator.alloc(u8, @intCast(usize, res));
                std.mem.copy(u8, p, foo[0..res]);
                return p;
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
        const env_map = try std.process.getEnvMap(arena.allocator());
        r2.fd_in = try std.fmt.parseInt(i32, env_map.get("R2PIPE_IN") orelse "-1", 10);
        r2.fd_out = try std.fmt.parseInt(i32, env_map.get("R2PIPE_OUT") orelse "-1", 10);
    }
    _ = file;
    return r2;
}
