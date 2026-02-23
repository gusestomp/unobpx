# unobpx

Decode and inspect [PerimeterX](https://www.humansecurity.com/) (HUMAN Security) protocol traffic.

PerimeterX uses multiple layers of obfuscation in its client-server communication. This library and CLI tool decode all three protocol layers, making PX traffic transparent for security research and analysis.

## What It Decodes

| Layer | Encoding | Description |
|-------|----------|-------------|
| **OB responses** | Base64 + XOR | Server responses from the PX collector (`ob` field in JSON) |
| **Sensor payloads** | XOR + Base64 + shuffle-interleave | The `payload` POST parameter in sensor requests |
| **OBS payloads** | AES-256-GCM | Encrypted Observer/SNR telemetry sent to `/si/*/obs` |

## Install

```bash
go install github.com/user/unobpx/cmd/unobpx@latest
```

Or as a library:

```bash
go get github.com/user/unobpx
```

## CLI Usage

### Decode OB Responses

OB responses are the server's reply to sensor POST requests. The `ob` field in the JSON response is Base64 + XOR encoded.

```bash
# With a known XOR key
unobpx ob "SGVsbG8gV29ybGQ=" 66

# Derive XOR key from the PX tag string automatically
unobpx ob "SGVsbG8gV29ybGQ=" --tag "IUMUAGcoCHQlTA=="
```

The tool decodes the response, parses all commands, and auto-identifies their roles (session ID, visitor ID, cookies, timestamps, etc.) regardless of which PX tag version generated them.

### Decode Sensor Payloads

Sensor payloads are the fingerprint/telemetry data sent from the browser to PX. You need the `payload`, `uuid`, and `sts` values from the POST parameters (all visible in the network tab).

```bash
unobpx sensor "<encoded_payload>" "<uuid>" "<sts>"
```

Outputs the decoded JSON — the raw fingerprint data PX collected from the browser.

### Decrypt OBS Payloads

OBS (Observer/SNR) payloads carry encrypted browser telemetry. They use AES-256-GCM with a key embedded in PX's `snr.js`.

```bash
unobpx obs "KAUHEVKF<base64_data>"
```

### Compute XOR Key

Every PX tag string maps to a specific XOR key used for OB encoding. The derivation is a simple hash function from `init.js`:

```bash
unobpx xorkey "IUMUAGcoCHQlTA=="
# Tag:     IUMUAGcoCHQlTA==
# XOR Key: 62 (0x3e)
```

## Library Usage

```go
package main

import (
    "fmt"
    "github.com/user/unobpx"
)

func main() {
    // Compute XOR key from a PX tag
    xorKey := unobpx.ComputeOBXORKey("IUMUAGcoCHQlTA==")

    // Decode an OB response
    decoded := unobpx.DecodeOB(obBase64String, xorKey)

    // Parse into structured commands
    cmds := unobpx.ParseCommands(decoded)

    // Auto-identify command roles (works across all tag versions)
    roles := unobpx.AutoMapCommands(decoded)
    fmt.Println("Session ID label:", roles[unobpx.RoleSID])
    fmt.Println("Visitor ID label:", roles[unobpx.RoleVID])

    // Extract cookies from OB
    cookies := unobpx.ExtractCookies(decoded)
    fmt.Println("_px3:", cookies["_px3"])

    // Decode a sensor payload
    json, _ := unobpx.DecodeSensor(encoded, uuid, sts)
    fmt.Println(json)

    // Decrypt OBS telemetry
    plain, _ := unobpx.DecryptOBS(wireData)
    fmt.Println(plain)
}
```

## Protocol Details

### OB Response Format

PX collector responses contain an `ob` field with the following encoding:

```
wire = base64(XOR(plaintext, key))
```

The XOR key is derived from the PX tag string using a hash function found in `init.js`:

```
e = 0
for each char in tag:
    e = (31 * e + charCode) % 2147483647
key = ((e % 900) + 100) % 128
```

Decoded OB text uses `~~~~` as command separator and `|` as field separator. Each command starts with a binary-like label (e.g., `oo1o11`) followed by parameter fields. Command labels rotate with each PX tag version, but value patterns are stable — `AutoMapCommands` identifies roles by analyzing values rather than labels.

### Sensor Payload Encoding

Sensor payloads (the `payload` POST parameter) use a multi-step obfuscation:

1. XOR each byte of the raw JSON with key `50`
2. Base64 encode the result
3. Derive a shuffle key: `base64(STS)` XOR'd byte-by-byte with `10`
4. Compute deterministic insertion indices from the shuffle key, payload length, and UUID
5. Interleave shuffle key characters into the Base64 string at the computed positions

The UUID and STS needed for decoding are sent as separate POST parameters in the same request.

### OBS Encryption

Observer payloads use AES-256-GCM:

- **Key**: `abC3UuT0Yte5FBGN2F6cQu0pegMgCMpr` (32 bytes, embedded in `snr.js`)
- **Wire format**: `"KAUHEVKF"` + `base64(nonce[12] + ciphertext + GCM_tag[16])`

The decrypted payload is JSON containing browser fingerprints, timing data, and behavioral telemetry.

## OB Command Roles

The `AutoMapCommands` function identifies these roles across any PX tag version:

| Role | Pattern | Description |
|------|---------|-------------|
| `sid` | 1 UUID field | Session ID |
| `vid` | UUID + `31536000` + `false` | Visitor ID (1-year TTL) |
| `cts` | UUID + `false`/`true` | CTS token |
| `cts_num` | 18-22 digit number | CTS numeric token |
| `cs` | 64-char hex | Session hash |
| `timestamp` | 12-14 digit number | Server timestamp (epoch ms) |
| `cls` | 1-6 digit number | CLS value |
| `token` | 15-25 char alphanumeric | Session token |
| `pow` | 5 fields, field[4] is 64-char hex | Proof-of-work challenge |
| `nonces` | 5 fields, long hex in [1] and [2] | Validation nonces |
| `callback` | 4+ fields, UUID in [1] | Callback data |
| `cookie` | 3+ fields, starts with `_px` | Set-Cookie instruction |
| `config` | Contains `bsco:` | Runtime configuration |
| `cs_mode` | `cu` or `cr` | Collector mode |
| `solve_result` | `0` or `-1` | Challenge result |

## License

MIT
