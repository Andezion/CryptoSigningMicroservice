const std = @import("std");
const http = @import("http.zig");
const crypto = @import("crypto.zig");
const storage = @import("storage.zig");

pub const ApiHandler = struct {
    allocator: std.mem.Allocator,
    crypto_core: *crypto.CryptoCore,
    key_storage: *storage.KeyStorage,

    pub fn init(allocator: std.mem.Allocator, crypto_core: *crypto.CryptoCore, key_storage: *storage.KeyStorage) ApiHandler {
        return .{
            .allocator = allocator,
            .crypto_core = crypto_core,
            .key_storage = key_storage,
        };
    }

    pub fn handle(self: *ApiHandler, allocator: std.mem.Allocator, request: http.HttpRequest) !http.HttpResponse {
        if (std.mem.eql(u8, request.path, "/health")) {
            return try http.HttpResponse.json(allocator, 200, "{\"status\":\"healthy\"}");
        }

        if (std.mem.eql(u8, request.path, "/api/keys/generate") and request.method == .POST) {
            return try self.handleGenerateKey(allocator, request.body);
        }

        if (std.mem.eql(u8, request.path, "/api/keys") and request.method == .GET) {
            return try self.handleListKeys(allocator);
        }

        if (std.mem.eql(u8, request.path, "/api/sign") and request.method == .POST) {
            return try self.handleSign(allocator, request.body);
        }

        if (std.mem.eql(u8, request.path, "/api/verify") and request.method == .POST) {
            return try self.handleVerify(allocator, request.body);
        }

        if (std.mem.startsWith(u8, request.path, "/api/keys/") and request.method == .DELETE) {
            const key_id = request.path[10..];
            return try self.handleDeleteKey(allocator, key_id);
        }

        return try http.HttpResponse.json(allocator, 404, "{\"error\":\"Not found\"}");
    }

    fn handleGenerateKey(self: *ApiHandler, allocator: std.mem.Allocator, body: []const u8) !http.HttpResponse {
        // Parse request
        const parsed = std.json.parseFromSlice(
            struct {
                key_id: []const u8,
                algorithm: ?[]const u8 = null,
            },
            allocator,
            body,
            .{},
        ) catch {
            return try http.HttpResponse.json(allocator, 400, "{\"error\":\"Invalid JSON\"}");
        };
        defer parsed.deinit();

        const req = parsed.value;
        const algorithm = if (req.algorithm) |alg|
            crypto.Algorithm.fromString(alg) catch .ed25519
        else
            .ed25519;

        // Generate keypair
        var keypair = try self.crypto_core.generateKeyPair(algorithm);
        defer keypair.deinit();

        // Store keypair
        try self.key_storage.storeKey(req.key_id, &keypair);

        // Get stored metadata
        const stored = self.key_storage.keys.get(req.key_id) orelse return error.StorageFailed;

        // Build response
        var response_buf = std.ArrayList(u8).init(allocator);
        defer response_buf.deinit();

        try std.json.stringify(.{
            .key_id = req.key_id,
            .algorithm = algorithm.toString(),
            .public_key = stored.metadata.public_key_base64,
            .created_at = stored.metadata.created_at,
        }, .{}, response_buf.writer());

        return http.HttpResponse.jsonOwned(201, try response_buf.toOwnedSlice());
    }

    fn handleListKeys(self: *ApiHandler, allocator: std.mem.Allocator) !http.HttpResponse {
        const keys = try self.key_storage.listKeys(allocator);
        defer allocator.free(keys);

        var response_buf = std.ArrayList(u8).init(allocator);
        defer response_buf.deinit();

        const writer = response_buf.writer();
        try writer.writeAll("{\"keys\":[");

        for (keys, 0..) |key, i| {
            if (i > 0) try writer.writeAll(",");
            try std.json.stringify(.{
                .key_id = key.id,
                .algorithm = key.algorithm.toString(),
                .public_key = key.public_key_base64,
                .created_at = key.created_at,
            }, .{}, writer);
        }

        try writer.writeAll("]}");

        return http.HttpResponse.jsonOwned(200, try response_buf.toOwnedSlice());
    }

    fn handleSign(self: *ApiHandler, allocator: std.mem.Allocator, body: []const u8) !http.HttpResponse {
        // Parse request
        const parsed = std.json.parseFromSlice(
            struct {
                key_id: []const u8,
                message: []const u8,
            },
            allocator,
            body,
            .{},
        ) catch {
            return try http.HttpResponse.json(allocator, 400, "{\"error\":\"Invalid JSON\"}");
        };
        defer parsed.deinit();

        const req = parsed.value;

        // Get key
        const secret_key = self.key_storage.getSecretKey(req.key_id) catch {
            return try http.HttpResponse.json(allocator, 404, "{\"error\":\"Key not found\"}");
        };

        const algorithm = try self.key_storage.getAlgorithm(req.key_id);

        // Decode message (assume base64)
        const decoder = std.base64.standard.Decoder;
        const message_len = try decoder.calcSizeForSlice(req.message);
        const message = try allocator.alloc(u8, message_len);
        defer allocator.free(message);
        try decoder.decode(message, req.message);

        // Sign
        var signature = try self.crypto_core.sign(algorithm, secret_key, message);
        defer signature.deinit();

        // Encode signature to base64
        const encoder = std.base64.standard.Encoder;
        const sig_b64_len = encoder.calcSize(signature.data.len);
        const sig_b64 = try allocator.alloc(u8, sig_b64_len);
        defer allocator.free(sig_b64);
        _ = encoder.encode(sig_b64, signature.data);

        // Build response
        var response_buf = std.ArrayList(u8).init(allocator);
        defer response_buf.deinit();

        try std.json.stringify(.{
            .key_id = req.key_id,
            .algorithm = algorithm.toString(),
            .signature = sig_b64,
        }, .{}, response_buf.writer());

        return http.HttpResponse.jsonOwned(200, try response_buf.toOwnedSlice());
    }

    fn handleVerify(self: *ApiHandler, allocator: std.mem.Allocator, body: []const u8) !http.HttpResponse {
        // Parse request
        const parsed = std.json.parseFromSlice(
            struct {
                key_id: []const u8,
                message: []const u8,
                signature: []const u8,
            },
            allocator,
            body,
            .{},
        ) catch {
            return try http.HttpResponse.json(allocator, 400, "{\"error\":\"Invalid JSON\"}");
        };
        defer parsed.deinit();

        const req = parsed.value;

        // Get public key
        const public_key = self.key_storage.getPublicKey(req.key_id) catch {
            return try http.HttpResponse.json(allocator, 404, "{\"error\":\"Key not found\"}");
        };
        defer allocator.free(public_key);

        const algorithm = try self.key_storage.getAlgorithm(req.key_id);

        // Decode message and signature
        const decoder = std.base64.standard.Decoder;

        const message_len = try decoder.calcSizeForSlice(req.message);
        const message = try allocator.alloc(u8, message_len);
        defer allocator.free(message);
        try decoder.decode(message, req.message);

        const sig_len = try decoder.calcSizeForSlice(req.signature);
        const signature = try allocator.alloc(u8, sig_len);
        defer allocator.free(signature);
        try decoder.decode(signature, req.signature);

        // Verify
        const valid = try self.crypto_core.verify(algorithm, public_key, message, signature);

        // Build response
        var response_buf = std.ArrayList(u8).init(allocator);
        defer response_buf.deinit();

        try std.json.stringify(.{
            .valid = valid,
            .key_id = req.key_id,
            .algorithm = algorithm.toString(),
        }, .{}, response_buf.writer());

        return http.HttpResponse.jsonOwned(200, try response_buf.toOwnedSlice());
    }

    fn handleDeleteKey(self: *ApiHandler, allocator: std.mem.Allocator, key_id: []const u8) !http.HttpResponse {
        self.key_storage.deleteKey(key_id) catch {
            return try http.HttpResponse.json(allocator, 404, "{\"error\":\"Key not found\"}");
        };

        return try http.HttpResponse.json(allocator, 200, "{\"message\":\"Key deleted\"}");
    }
};
