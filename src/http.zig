const std = @import("std");

pub const HttpServer = struct {
    allocator: std.mem.Allocator,
    server: std.net.Server,
    host: []const u8,
    port: u16,
    running: bool,

    pub fn init(allocator: std.mem.Allocator, host: []const u8, port: u16) !HttpServer {
        const address = try std.net.Address.parseIp(host, port);
        const server = try address.listen(.{
            .reuse_address = true,
        });

        return HttpServer{
            .allocator = allocator,
            .server = server,
            .host = host,
            .port = port,
            .running = false,
        };
    }

    pub fn deinit(self: *HttpServer) void {
        self.server.deinit();
    }

    pub fn start(self: *HttpServer, handler: *RequestHandler) !void {
        self.running = true;
        std.log.info("Server listening on {s}:{d}", .{ self.host, self.port });

        while (self.running) {
            const connection = self.server.accept() catch |err| {
                std.log.err("Failed to accept connection: {}", .{err});
                continue;
            };

            self.handleConnection(connection, handler) catch |err| {
                std.log.err("Failed to handle connection: {}", .{err});
            };
        }
    }

    fn handleConnection(self: *HttpServer, connection: std.net.Server.Connection, handler: *RequestHandler) !void {
        defer connection.stream.close();

        var buffer: [8192]u8 = undefined;
        const bytes_read = try connection.stream.read(&buffer);

        if (bytes_read == 0) return;

        const request_data = buffer[0..bytes_read];

        // Parse HTTP request
        const request = try self.parseRequest(request_data);

        // Route to handler
        const response = try handler.handle(self.allocator, request);
        defer response.deinit(self.allocator);

        // Send response
        try self.sendResponse(connection.stream, response);
    }

    fn parseRequest(self: *HttpServer, data: []const u8) !HttpRequest {
        _ = self;

        var lines = std.mem.splitScalar(u8, data, '\n');
        const first_line = lines.next() orelse return error.InvalidRequest;

        // Parse request line: METHOD PATH HTTP/VERSION
        var parts = std.mem.splitScalar(u8, first_line, ' ');
        const method_str = parts.next() orelse return error.InvalidRequest;
        const path = parts.next() orelse return error.InvalidRequest;

        const method = if (std.mem.eql(u8, method_str, "GET"))
            HttpMethod.GET
        else if (std.mem.eql(u8, method_str, "POST"))
            HttpMethod.POST
        else if (std.mem.eql(u8, method_str, "DELETE"))
            HttpMethod.DELETE
        else
            HttpMethod.GET;

        // Find body (after empty line)
        var body: []const u8 = "";
        var found_empty = false;
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, &std.ascii.whitespace);
            if (trimmed.len == 0) {
                found_empty = true;
                continue;
            }
            if (found_empty) {
                body = trimmed;
                break;
            }
        }

        return HttpRequest{
            .method = method,
            .path = path,
            .body = body,
        };
    }

    fn sendResponse(self: *HttpServer, stream: std.net.Stream, response: HttpResponse) !void {
        _ = self;

        const status_text = switch (response.status) {
            200 => "OK",
            201 => "Created",
            400 => "Bad Request",
            404 => "Not Found",
            500 => "Internal Server Error",
            else => "Unknown",
        };

        var writer = stream.writer();

        // Status line
        try writer.print("HTTP/1.1 {d} {s}\r\n", .{ response.status, status_text });

        // Headers
        try writer.print("Content-Type: {s}\r\n", .{response.content_type});
        try writer.print("Content-Length: {d}\r\n", .{response.body.len});
        try writer.writeAll("Connection: close\r\n");
        try writer.writeAll("\r\n");

        // Body
        try writer.writeAll(response.body);
    }
};

pub const HttpMethod = enum {
    GET,
    POST,
    DELETE,
};

pub const HttpRequest = struct {
    method: HttpMethod,
    path: []const u8,
    body: []const u8,
};

pub const HttpResponse = struct {
    status: u16,
    content_type: []const u8,
    body: []const u8,

    pub fn deinit(self: *const HttpResponse, allocator: std.mem.Allocator) void {
        allocator.free(self.body);
    }

    pub fn json(allocator: std.mem.Allocator, status: u16, data: []const u8) !HttpResponse {
        const body = try allocator.dupe(u8, data);
        return HttpResponse{
            .status = status,
            .content_type = "application/json",
            .body = body,
        };
    }

    pub fn jsonOwned(status: u16, body: []const u8) HttpResponse {
        return HttpResponse{
            .status = status,
            .content_type = "application/json",
            .body = body,
        };
    }
};

pub const RequestHandler = struct {
    handle: *const fn (allocator: std.mem.Allocator, request: HttpRequest) anyerror!HttpResponse,
};
