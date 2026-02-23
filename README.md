# unobpx

See through PerimeterX. Every layer, decoded.

[PerimeterX](https://www.humansecurity.com/) (now HUMAN Security) wraps its client-server protocol in three layers of obfuscation — XOR, shuffle-interleave, and AES-256-GCM. This tool strips all of them.

Open your browser devtools, capture PX traffic, and feed it to `unobpx`. Out comes the raw protocol: session commands, fingerprint JSON, encrypted telemetry — all in plaintext.

## What It Decodes

| Layer | What You See | What's Inside |
|-------|-------------|---------------|
| **OB responses** | Base64 blob in the `ob` JSON field | Session IDs, cookies, PoW challenges, config, timestamps |
| **Sensor payloads** | Garbled `payload` POST parameter | Full browser fingerprint JSON (every field PX collects) |
| **OBS telemetry** | `KAUHEVKF...` encrypted blob | WebGL, fonts, screen, timing, behavioral data |

## Install

```bash
go install github.com/sardanioss/unobpx/cmd/unobpx@latest
```

Or as a library:

```bash
go get github.com/sardanioss/unobpx
```

## Quick Start

```bash
# Derive the XOR key from any PX tag
unobpx xorkey "IUMUAGcoCHQlTA=="
# Tag:     IUMUAGcoCHQlTA==
# XOR Key: 62 (0x3e)

# Decode an OB response — auto-identifies all command roles
unobpx ob "<base64_ob_string>" --tag "IUMUAGcoCHQlTA=="

# Decode a sensor payload (uuid and sts from the same POST request)
unobpx sensor "<encoded_payload>" "<uuid>" "<sts>"

# Decrypt OBS encrypted telemetry
unobpx obs "KAUHEVKF<base64_data>"
```

## CLI

### `unobpx ob` — Decode Collector Responses

The PX collector replies with an `ob` field containing Base64 + XOR encoded commands. This decodes it and auto-maps every command to its role — session IDs, visitor IDs, cookies, PoW challenges, timestamps — regardless of which PX tag version generated them.

```bash
# Using a known XOR key
unobpx ob "SGVsbG8gV29ybGQ=" 66

# Or let it derive the key from the tag
unobpx ob "SGVsbG8gV29ybGQ=" --tag "IUMUAGcoCHQlTA=="
```

PX rotates command labels with every tag version. `unobpx` doesn't care — it identifies commands by their value patterns, not their labels.

### `unobpx sensor` — Decode Sensor Payloads

The `payload` POST parameter in every sensor request carries the browser fingerprint. It's obfuscated with XOR, Base64, and a shuffle-interleave keyed by the UUID and server timestamp.

```bash
unobpx sensor "<encoded_payload>" "<uuid>" "<sts>"
```

All three values are visible as separate POST parameters in the same request. Output is the raw fingerprint JSON.

### `unobpx obs` — Decrypt Observer Telemetry

OBS payloads are AES-256-GCM encrypted with a key embedded in PX's `snr.js`. This decrypts them.

```bash
unobpx obs "KAUHEVKF<base64_data>"
```

### `unobpx xorkey` — Tag to XOR Key

Every PX tag string deterministically maps to an XOR key. The hash function (from `init.js`):

```
e = 0
for each char in tag:
    e = (31 * e + charCode) % 2147483647
key = ((e % 900) + 100) % 128
```

```bash
unobpx xorkey "Zj4TeyhNFxB5"
# Tag:     Zj4TeyhNFxB5
# XOR Key: 66 (0x42)
```

## Library Usage

```go
import "github.com/sardanioss/unobpx"

// Compute XOR key from a PX tag
xorKey := unobpx.ComputeOBXORKey("IUMUAGcoCHQlTA==")

// Decode an OB response
decoded := unobpx.DecodeOB(obBase64, xorKey)

// Parse into structured commands
cmds := unobpx.ParseCommands(decoded)

// Auto-identify command roles across any tag version
roles := unobpx.AutoMapCommands(decoded)
fmt.Println("SID label:", roles[unobpx.RoleSID])
fmt.Println("VID label:", roles[unobpx.RoleVID])

// Extract cookies
cookies := unobpx.ExtractCookies(decoded)

// Decode a sensor payload
json, _ := unobpx.DecodeSensor(encoded, uuid, sts)

// Decrypt OBS telemetry
plain, _ := unobpx.DecryptOBS(wireData)
```

## Protocol Reference

### OB Response Wire Format

```
wire = base64(XOR(plaintext, key))
```

Decoded text uses `~~~~` as command separator and `|` as field separator. Each command starts with a binary-like label (e.g., `oo1o11`) followed by parameters.

### OB Command Roles

| Role | Pattern | What It Is |
|------|---------|------------|
| `sid` | 1 UUID field | Session ID |
| `vid` | UUID + `31536000` + `false` | Visitor ID (1-year TTL) |
| `cts` | UUID + `false`/`true` | CTS token |
| `cts_num` | 18-22 digit number | CTS numeric token |
| `cs` | 64-char hex | Session hash |
| `timestamp` | 12-14 digit number | Server timestamp (epoch ms) |
| `cls` | 1-6 digit number | CLS value |
| `token` | 15-25 char alphanumeric | Session token |
| `pow` | 5 fields, field[4] is 64-char hex | Proof-of-work challenge |
| `nonces` | 5 fields, long hex in [1],[2] | Validation nonces |
| `callback` | 4+ fields, UUID in [1] | Callback data |
| `cookie` | 3+ fields, starts with `_px` | Set-Cookie instruction |
| `config` | Contains `bsco:` | Runtime configuration |
| `cs_mode` | `cu` or `cr` | Collector mode |
| `solve_result` | `0` or `-1` | Challenge result |

### Sensor Payload Encoding

1. XOR raw JSON with key `50`
2. Base64 encode
3. Derive shuffle key: `base64(STS)` XOR'd with `10`
4. Compute deterministic insertion indices from shuffle key + payload length + UUID
5. Interleave shuffle key characters at computed positions

The UUID and STS are sent as separate POST parameters alongside the payload.

### OBS Encryption

- **Algorithm**: AES-256-GCM
- **Key**: `abC3UuT0Yte5FBGN2F6cQu0pegMgCMpr` (32 bytes, from `snr.js`)
- **Wire format**: `"KAUHEVKF"` + `base64(nonce[12] + ciphertext + GCM_tag[16])`

## Full PX Research & Services

This is the decode/analysis side of a much deeper PerimeterX research project.

If you're interested in the complete research, full protocol implementation, or commercial API access — reach out:

- Discord: **@sardanioss**
- Email: **sakshamsolanki126@gmail.com**

## License

MIT
