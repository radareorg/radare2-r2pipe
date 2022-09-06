const std = @import("std");
const print = @import("std").debug.print;

pub const R2PipeMode = enum {
    env,
    api,
    // http,
};

pub const R2Pipe = struct {
    fd_in: i32 = -1,
    fd_out: i32 = -1,

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
                return foo[0..res];
            }
        }
        return "";
    }

    pub fn quit(r2: R2Pipe) void {
        _ = r2.cmd("q!!");
    }
};

pub fn open(file: []const u8) !R2Pipe {
    var r2 = R2Pipe{};
    if (std.mem.eql(u8, file, "")) {
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        const env_map = try std.process.getEnvMap(arena.allocator());
        r2.fd_in = try std.fmt.parseInt(i32, env_map.get("R2PIPE_IN") orelse "-1", 10);
        r2.fd_out = try std.fmt.parseInt(i32, env_map.get("R2PIPE_OUT") orelse "-1", 10);
        arena.deinit();
    }
    return r2;
}
