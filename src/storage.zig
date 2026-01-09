const std = @import("std");
const crypto = @import("crypto.zig");

pub const KeyMetadata = struct {
    id: []const u8,
    algorithm: crypto.Algorithm,
    created_at: i64,
    public_key_base64: []const u8,
};

pub const KeyStorage = struct {
    allocator: std.mem.Allocator,
    keys_dir: []const u8,
    keys: std.StringHashMap(StoredKey),

    const StoredKey = struct {
        metadata: KeyMetadata,
        secret_key: []u8,
        allocator: std.mem.Allocator,

        pub fn deinit(self: *StoredKey) void {
            self.allocator.free(self.metadata.id);
            self.allocator.free(self.metadata.public_key_base64);
            @memset(self.secret_key, 0);
            self.allocator.free(self.secret_key);
        }
    };

    pub fn init(allocator: std.mem.Allocator, keys_dir: []const u8) !KeyStorage {
        std.fs.cwd().makePath(keys_dir) catch |err| {
            if (err != error.PathAlreadyExists) return err;
        };

        var storage = KeyStorage{
            .allocator = allocator,
            .keys_dir = keys_dir,
            .keys = std.StringHashMap(StoredKey).init(allocator),
        };

        try storage.loadKeys();

        return storage;
    }

    pub fn deinit(self: *KeyStorage) void {
        var it = self.keys.valueIterator();
        while (it.next()) |stored_key| {
            var key = stored_key.*;
            key.deinit();
        }
        self.keys.deinit();
    }

    pub fn storeKey(self: *KeyStorage, id: []const u8, keypair: *crypto.KeyPair) !void {
        const encoder = std.base64.standard.Encoder;
        const public_key_b64_len = encoder.calcSize(keypair.public_key.len);
        const public_key_b64 = try self.allocator.alloc(u8, public_key_b64_len);
        errdefer self.allocator.free(public_key_b64);
        _ = encoder.encode(public_key_b64, keypair.public_key);

        const secret_key = try self.allocator.alloc(u8, keypair.secret_key.len);
        errdefer self.allocator.free(secret_key);
        @memcpy(secret_key, keypair.secret_key);

        const id_copy = try self.allocator.dupe(u8, id);
        errdefer self.allocator.free(id_copy);

        const metadata = KeyMetadata{
            .id = id_copy,
            .algorithm = keypair.algorithm,
            .created_at = std.time.timestamp(),
            .public_key_base64 = public_key_b64,
        };

        const stored_key = StoredKey{
            .metadata = metadata,
            .secret_key = secret_key,
            .allocator = self.allocator,
        };

        try self.keys.put(id_copy, stored_key);

        try self.saveKeyToDisk(id, &stored_key);
    }

    pub fn getSecretKey(self: *KeyStorage, id: []const u8) ![]const u8 {
        const stored = self.keys.get(id) orelse return error.KeyNotFound;
        return stored.secret_key;
    }

    pub fn getPublicKey(self: *KeyStorage, id: []const u8) ![]const u8 {
        const stored = self.keys.get(id) orelse return error.KeyNotFound;

        const decoder = std.base64.standard.Decoder;
        const public_key_len = try decoder.calcSizeForSlice(stored.metadata.public_key_base64);
        const public_key = try self.allocator.alloc(u8, public_key_len);
        errdefer self.allocator.free(public_key);

        try decoder.decode(public_key, stored.metadata.public_key_base64);
        return public_key;
    }

    pub fn getAlgorithm(self: *KeyStorage, id: []const u8) !crypto.Algorithm {
        const stored = self.keys.get(id) orelse return error.KeyNotFound;
        return stored.metadata.algorithm;
    }

    pub fn listKeys(self: *KeyStorage, allocator: std.mem.Allocator) ![]KeyMetadata {
        var result = try allocator.alloc(KeyMetadata, self.keys.count());
        var i: usize = 0;

        var it = self.keys.valueIterator();
        while (it.next()) |stored| {
            result[i] = stored.metadata;
            i += 1;
        }

        return result;
    }

    pub fn deleteKey(self: *KeyStorage, id: []const u8) !void {
        const entry = self.keys.fetchRemove(id) orelse return error.KeyNotFound;
        var stored = entry.value;
        stored.deinit();

        var path_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buf, "{s}/{s}.key", .{ self.keys_dir, id });
        try std.fs.cwd().deleteFile(path);
    }

    fn saveKeyToDisk(self: *KeyStorage, id: []const u8, stored: *const StoredKey) !void {
        var path_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buf, "{s}/{s}.key", .{ self.keys_dir, id });

        const file = try std.fs.cwd().createFile(path, .{});
        defer file.close();

        var buf_writer = std.io.bufferedWriter(file.writer());
        const writer = buf_writer.writer();

        const encoder = std.base64.standard.Encoder;
        const secret_key_b64_len = encoder.calcSize(stored.secret_key.len);
        const secret_key_b64 = try self.allocator.alloc(u8, secret_key_b64_len);
        defer self.allocator.free(secret_key_b64);
        _ = encoder.encode(secret_key_b64, stored.secret_key);

        try writer.print("{{\"id\":\"{s}\",\"algorithm\":\"{s}\",\"created_at\":{d},\"public_key\":\"{s}\",\"secret_key\":\"{s}\"}}\n", .{
            stored.metadata.id,
            stored.metadata.algorithm.toString(),
            stored.metadata.created_at,
            stored.metadata.public_key_base64,
            secret_key_b64,
        });

        try buf_writer.flush();
    }

    fn loadKeys(self: *KeyStorage) !void {
        var dir = std.fs.cwd().openDir(self.keys_dir, .{ .iterate = true }) catch |err| {
            if (err == error.FileNotFound) return;
            return err;
        };
        defer dir.close();

        var it = dir.iterate();
        while (try it.next()) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.name, ".key")) continue;

            self.loadKeyFromFile(entry.name) catch |err| {
                std.log.warn("Failed to load key file {s}: {}", .{ entry.name, err });
                continue;
            };
        }
    }

    fn loadKeyFromFile(self: *KeyStorage, filename: []const u8) !void {
        var path_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ self.keys_dir, filename });

        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();

        const content = try file.readToEndAlloc(self.allocator, 1024 * 1024);
        defer self.allocator.free(content);

        const parsed = try std.json.parseFromSlice(
            struct {
                id: []const u8,
                algorithm: []const u8,
                created_at: i64,
                public_key: []const u8,
                secret_key: []const u8,
            },
            self.allocator,
            content,
            .{},
        );
        defer parsed.deinit();

        const data = parsed.value;

        const decoder = std.base64.standard.Decoder;
        const public_key_b64 = try self.allocator.alloc(u8, data.public_key.len);
        errdefer self.allocator.free(public_key_b64);
        @memcpy(public_key_b64, data.public_key);

        const secret_key_len = try decoder.calcSizeForSlice(data.secret_key);
        const secret_key = try self.allocator.alloc(u8, secret_key_len);
        errdefer self.allocator.free(secret_key);
        try decoder.decode(secret_key, data.secret_key);

        const id_copy = try self.allocator.dupe(u8, data.id);
        errdefer self.allocator.free(id_copy);

        const algorithm = try crypto.Algorithm.fromString(data.algorithm);

        const metadata = KeyMetadata{
            .id = id_copy,
            .algorithm = algorithm,
            .created_at = data.created_at,
            .public_key_base64 = public_key_b64,
        };

        const stored_key = StoredKey{
            .metadata = metadata,
            .secret_key = secret_key,
            .allocator = self.allocator,
        };

        try self.keys.put(id_copy, stored_key);
    }
};
