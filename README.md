# CryptoSign - Cryptographic Signing Microservice

A high-performance cryptographic signing microservice built in Zig, providing REST API endpoints for digital signature operations.

## Features

**Multiple Algorithms**
- Ed25519 (default, fast and secure)
- ECDSA P-256 (NIST curve)

**Key Management**
- Generate new keypairs
- Secure file-based storage
- List and delete keys
- Base64-encoded keys

**REST API**
- JSON request/response
- Simple HTTP interface
- Health check endpoint

**Security**
- Cryptographically secure random key generation
- Secure key storage with zero-out on deletion
- Standard Zig crypto library

## Architecture

```
┌─────────────────┐
│   REST API      │  HTTP JSON endpoints
├─────────────────┤
│   API Handler   │  Request routing & validation
├─────────────────┤
│   Crypto Core   │  Ed25519 & ECDSA operations
├─────────────────┤
│  Key Storage    │  File-based key persistence
└─────────────────┘
```

## Quick Start

### Build

```bash
zig build
```

### Configure

Copy the example config:
```bash
cp config.example.json config.json
```

Edit `config.json` to customize:
```json
{
  "server": {
    "host": "127.0.0.1",
    "port": 8080
  },
  "storage": {
    "keys_directory": "./keys"
  }
}
```

### Run

```bash
zig build run
```

The service will start on `http://127.0.0.1:8080`

### Run Tests

```bash
zig build test
```

## API Reference

### Health Check

```bash
GET /health
```

Response:
```json
{"status": "healthy"}
```

### Generate Keypair

```bash
POST /api/keys/generate
Content-Type: application/json

{
  "key_id": "my-signing-key",
  "algorithm": "ed25519"
}
```

Response:
```json
{
  "key_id": "my-signing-key",
  "algorithm": "ed25519",
  "public_key": "base64_encoded_public_key",
  "created_at": 1736440800
}
```

Supported algorithms: `ed25519`, `ecdsa-p256`

### List Keys

```bash
GET /api/keys
```

Response:
```json
{
  "keys": [
    {
      "key_id": "my-signing-key",
      "algorithm": "ed25519",
      "public_key": "base64_encoded_public_key",
      "created_at": 1736440800
    }
  ]
}
```

### Sign Data

```bash
POST /api/sign
Content-Type: application/json

{
  "key_id": "my-signing-key",
  "message": "base64_encoded_message"
}
```

Response:
```json
{
  "key_id": "my-signing-key",
  "algorithm": "ed25519",
  "signature": "base64_encoded_signature"
}
```

### Verify Signature

```bash
POST /api/verify
Content-Type: application/json

{
  "key_id": "my-signing-key",
  "message": "base64_encoded_message",
  "signature": "base64_encoded_signature"
}
```

Response:
```json
{
  "valid": true,
  "key_id": "my-signing-key",
  "algorithm": "ed25519"
}
```

### Delete Key

```bash
DELETE /api/keys/{key_id}
```

Response:
```json
{"message": "Key deleted"}
```

## Example Usage

### Using curl

1. **Generate a key:**
```bash
curl -X POST http://localhost:8080/api/keys/generate \
  -H "Content-Type: application/json" \
  -d '{"key_id": "test-key", "algorithm": "ed25519"}'
```

2. **Sign a message:**
```bash
# First, encode your message to base64
MESSAGE=$(echo -n "Hello, World!" | base64)

curl -X POST http://localhost:8080/api/sign \
  -H "Content-Type: application/json" \
  -d "{\"key_id\": \"test-key\", \"message\": \"$MESSAGE\"}"
```

3. **Verify a signature:**
```bash
curl -X POST http://localhost:8080/api/verify \
  -H "Content-Type: application/json" \
  -d '{"key_id": "test-key", "message": "SGVsbG8sIFdvcmxkIQ==", "signature": "..."}'
```

4. **List all keys:**
```bash
curl http://localhost:8080/api/keys
```

## Project Structure

```
CryptoSign/
├── build.zig              # Build configuration
├── config.example.json    # Example configuration
├── .gitignore
├── README.md
└── src/
    ├── main.zig          # Entry point & server setup
    ├── config.zig        # Configuration management
    ├── http.zig          # HTTP server implementation
    ├── api.zig           # API request handlers
    ├── crypto.zig        # Cryptographic operations
    └── storage.zig       # Key storage management
```

## Security Considerations

- Keys are stored in files with base64 encoding
- Secret keys are zeroed out before memory deallocation
- Cryptographically secure random number generation
- For production use, consider:
  - Hardware Security Module (HSM) integration
  - Key encryption at rest
  - TLS/HTTPS for API endpoints
  - Authentication and authorization
  - Rate limiting and request validation

## Development

### Prerequisites

- Zig 0.13.0 or later

### Building

```bash
# Debug build
zig build

# Release build
zig build -Doptimize=ReleaseFast

# Run directly
zig build run

# Run tests
zig build test
```

## Extending to HSM

To integrate with an HSM (Hardware Security Module):

1. Create a new `hsm.zig` module
2. Implement the PKCS#11 or vendor-specific API
3. Add HSM backend selection in `config.json`
4. Modify `storage.zig` to support HSM key references
5. Update `crypto.zig` to offload operations to HSM

Example HSM configuration:
```json
{
  "storage": {
    "backend": "hsm",
    "hsm_config": {
      "library": "/usr/lib/libpkcs11.so",
      "slot": 0,
      "pin": "encrypted_pin"
    }
  }
}
```


