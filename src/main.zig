const std = @import("std");
const config = @import("config.zig");
const http = @import("http.zig");
const crypto = @import("crypto.zig");
const storage = @import("storage.zig");
const api = @import("api.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var cfg = config.Config.loadFromFile(allocator, "config.json") catch |err| {
        if (err == error.FileNotFound) {
            std.log.warn("config.json not found, using defaults", .{});
            try config.Config.default(allocator);
        } else {
            return err;
        }
    };
    defer cfg.deinit(allocator);

    std.log.info("Starting CryptoSign microservice...", .{});
    std.log.info("Configuration:", .{});
    std.log.info("  Host: {s}", .{cfg.server_host});
    std.log.info("  Port: {d}", .{cfg.server_port});
    std.log.info("  Keys directory: {s}", .{cfg.keys_directory});

    // Initialize crypto core
    var crypto_core = crypto.CryptoCore.init(allocator);

    // Initialize key storage
    var key_storage = try storage.KeyStorage.init(allocator, cfg.keys_directory);
    defer key_storage.deinit();

    const keys = try key_storage.listKeys(allocator);
    defer allocator.free(keys);
    std.log.info("Loaded {d} existing keys", .{keys.len});

    // Initialize API handler
    var api_handler = api.ApiHandler.init(allocator, &crypto_core, &key_storage);

    // Create request handler wrapper
    const Handler = struct {
        handler: *api.ApiHandler,

        pub fn handle(self: *const @This(), allocator_arg: std.mem.Allocator, request: http.HttpRequest) !http.HttpResponse {
            return try self.handler.handle(allocator_arg, request);
        }
    };

    var handler = Handler{ .handler = &api_handler };
    var request_handler = http.RequestHandler{
        .handle = @ptrCast(&Handler.handle),
    };

    // Start HTTP server
    var server = try http.HttpServer.init(allocator, cfg.server_host, cfg.server_port);
    defer server.deinit();

    std.log.info("🔐 CryptoSign API ready!", .{});
    std.log.info("Endpoints:", .{});
    std.log.info("  GET  /health", .{});
    std.log.info("  POST /api/keys/generate", .{});
    std.log.info("  GET  /api/keys", .{});
    std.log.info("  POST /api/sign", .{});
    std.log.info("  POST /api/verify", .{});
    std.log.info("  DELETE /api/keys/{{key_id}}", .{});

    _ = &handler;
    try server.start(&request_handler);
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("crypto.zig");
}
