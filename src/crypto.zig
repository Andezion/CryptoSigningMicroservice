const std = @import("std");

pub const Algorithm = enum {
    ed25519,
    ecdsa_p256,

    pub fn fromString(str: []const u8) !Algorithm {
        if (std.mem.eql(u8, str, "ed25519")) return .ed25519;
        if (std.mem.eql(u8, str, "ecdsa-p256")) return .ecdsa_p256;
        return error.UnsupportedAlgorithm;
    }

    pub fn toString(self: Algorithm) []const u8 {
        return switch (self) {
            .ed25519 => "ed25519",
            .ecdsa_p256 => "ecdsa-p256",
        };
    }
};

pub const KeyPair = struct {
    algorithm: Algorithm,
    public_key: []u8,
    secret_key: []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *KeyPair) void {
        self.allocator.free(self.public_key);
        @memset(self.secret_key, 0);
        self.allocator.free(self.secret_key);
    }
};

pub const Signature = struct {
    data: []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Signature) void {
        self.allocator.free(self.data);
    }
};

pub const CryptoCore = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) CryptoCore {
        return .{ .allocator = allocator };
    }

    pub fn generateKeyPair(self: *CryptoCore, algorithm: Algorithm) !KeyPair {
        return switch (algorithm) {
            .ed25519 => try self.generateEd25519KeyPair(),
            .ecdsa_p256 => try self.generateEcdsaP256KeyPair(),
        };
    }

    fn generateEd25519KeyPair(self: *CryptoCore) !KeyPair {
        const Ed25519 = std.crypto.sign.Ed25519;

        var seed: [32]u8 = undefined;
        std.crypto.random.bytes(&seed);

        const secret = Ed25519.SecretKey.fromBytes(seed);
        const public = try secret.publicKey();

        // Zero out the seed
        @memset(&seed, 0);

        const public_key = try self.allocator.alloc(u8, Ed25519.public_length);
        const secret_key = try self.allocator.alloc(u8, Ed25519.secret_length);

        @memcpy(public_key, &public.bytes);
        @memcpy(secret_key, &secret.bytes);

        return KeyPair{
            .algorithm = .ed25519,
            .public_key = public_key,
            .secret_key = secret_key,
            .allocator = self.allocator,
        };
    }

    fn generateEcdsaP256KeyPair(self: *CryptoCore) !KeyPair {
        const Ecdsa = std.crypto.sign.ecdsa;
        const P256 = Ecdsa.EcdsaP256Sha256;

        const key_pair = try P256.KeyPair.create(null);

        const public_key = try self.allocator.alloc(u8, 65);
        const secret_key = try self.allocator.alloc(u8, 32);

        const public_point = key_pair.public_key.toUncompressedSec1();
        @memcpy(public_key, &public_point);

        const secret_bytes = key_pair.secret_key.toBytes();
        @memcpy(secret_key, &secret_bytes);

        return KeyPair{
            .algorithm = .ecdsa_p256,
            .public_key = public_key,
            .secret_key = secret_key,
            .allocator = self.allocator,
        };
    }

    pub fn sign(self: *CryptoCore, algorithm: Algorithm, secret_key: []const u8, message: []const u8) !Signature {
        return switch (algorithm) {
            .ed25519 => try self.signEd25519(secret_key, message),
            .ecdsa_p256 => try self.signEcdsaP256(secret_key, message),
        };
    }

    fn signEd25519(self: *CryptoCore, secret_key: []const u8, message: []const u8) !Signature {
        const Ed25519 = std.crypto.sign.Ed25519;

        if (secret_key.len != Ed25519.secret_length) {
            return error.InvalidSecretKey;
        }

        var key_pair: Ed25519.KeyPair = undefined;
        @memcpy(&key_pair.secret_key.bytes, secret_key);

        key_pair.public_key = try Ed25519.publicKeyFromSecretKey(key_pair.secret_key);

        const sig = try Ed25519.sign(message, key_pair, null);

        const sig_data = try self.allocator.alloc(u8, Ed25519.signature_length);
        @memcpy(sig_data, &sig.toBytes());

        return Signature{
            .data = sig_data,
            .allocator = self.allocator,
        };
    }

    fn signEcdsaP256(self: *CryptoCore, secret_key: []const u8, message: []const u8) !Signature {
        const Ecdsa = std.crypto.sign.ecdsa;
        const P256 = Ecdsa.EcdsaP256Sha256;

        if (secret_key.len != 32) {
            return error.InvalidSecretKey;
        }

        var secret_bytes: [32]u8 = undefined;
        @memcpy(&secret_bytes, secret_key);

        const secret = try P256.SecretKey.fromBytes(secret_bytes);
        const key_pair = try P256.KeyPair.fromSecretKey(secret);

        const sig_obj = try P256.sign(message, key_pair, null);
        const sig_der = sig_obj.toDer();

        const sig_data = try self.allocator.alloc(u8, sig_der.len);
        @memcpy(sig_data, &sig_der);

        return Signature{
            .data = sig_data,
            .allocator = self.allocator,
        };
    }

    pub fn verify(self: *CryptoCore, algorithm: Algorithm, public_key: []const u8, message: []const u8, signature: []const u8) !bool {
        _ = self;
        return switch (algorithm) {
            .ed25519 => verifyEd25519(public_key, message, signature),
            .ecdsa_p256 => verifyEcdsaP256(public_key, message, signature),
        };
    }

    fn verifyEd25519(public_key: []const u8, message: []const u8, signature: []const u8) !bool {
        const Ed25519 = std.crypto.sign.Ed25519;

        if (public_key.len != Ed25519.public_length) {
            return error.InvalidPublicKey;
        }

        if (signature.len != Ed25519.signature_length) {
            return error.InvalidSignature;
        }

        var pub_key: Ed25519.PublicKey = undefined;
        @memcpy(&pub_key.bytes, public_key);

        var sig: Ed25519.Signature = undefined;
        @memcpy(&sig.bytes, signature);

        sig.verify(message, pub_key) catch return false;
        return true;
    }

    fn verifyEcdsaP256(public_key: []const u8, message: []const u8, signature: []const u8) !bool {
        const Ecdsa = std.crypto.sign.ecdsa;
        const P256 = Ecdsa.EcdsaP256Sha256;

        if (public_key.len != 65) {
            return error.InvalidPublicKey;
        }

        const pub_key = try P256.PublicKey.fromSec1(public_key);

        var sig_bytes: [P256.Signature.der_encoded_max_length]u8 = undefined;
        if (signature.len > sig_bytes.len) {
            return error.InvalidSignature;
        }
        @memcpy(sig_bytes[0..signature.len], signature);

        const sig = P256.Signature.fromDer(sig_bytes[0..signature.len]) catch return false;

        sig.verify(message, pub_key) catch return false;
        return true;
    }
};

test "Ed25519 keypair generation" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var crypto = CryptoCore.init(allocator);
    var keypair = try crypto.generateKeyPair(.ed25519);
    defer keypair.deinit();

    try std.testing.expect(keypair.public_key.len == 32);
    try std.testing.expect(keypair.secret_key.len == 64);
}

test "Ed25519 sign and verify" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var crypto = CryptoCore.init(allocator);
    var keypair = try crypto.generateKeyPair(.ed25519);
    defer keypair.deinit();

    const message = "Hello, CryptoSign!";

    var signature = try crypto.sign(.ed25519, keypair.secret_key, message);
    defer signature.deinit();

    const valid = try crypto.verify(.ed25519, keypair.public_key, message, signature.data);
    try std.testing.expect(valid);

    const invalid = try crypto.verify(.ed25519, keypair.public_key, "Wrong message", signature.data);
    try std.testing.expect(!invalid);
}
