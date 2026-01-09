const std = @import("std");

pub const Config = struct {
    server_host: []const u8,
    server_port: u16,
    keys_directory: []const u8,

    pub fn loadFromFile(allocator: std.mem.Allocator, path: []const u8) !Config {
        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();

        const content = try file.readToEndAlloc(allocator, 1024 * 1024);
        defer allocator.free(content);

        const parsed = try std.json.parseFromSlice(
            struct {
                server: struct {
                    host: []const u8,
                    port: u16,
                },
                storage: struct {
                    keys_directory: []const u8,
                },
            },
            allocator,
            content,
            .{},
        );
        defer parsed.deinit();

        return Config{
            .server_host = try allocator.dupe(u8, parsed.value.server.host),
            .server_port = parsed.value.server.port,
            .keys_directory = try allocator.dupe(u8, parsed.value.storage.keys_directory),
        };
    }

    pub fn default(allocator: std.mem.Allocator) !Config {
        return Config{
            .server_host = try allocator.dupe(u8, "127.0.0.1"),
            .server_port = 8080,
            .keys_directory = try allocator.dupe(u8, "./keys"),
        };
    }

    pub fn deinit(self: *Config, allocator: std.mem.Allocator) void {
        allocator.free(self.server_host);
        allocator.free(self.keys_directory);
    }
};
