// Package unobpx decodes PerimeterX (HUMAN Security) protocol data.
//
// PerimeterX uses multiple layers of obfuscation in its client-server
// communication. This package provides tools to decode and inspect
// that traffic for security research and analysis.
//
// It handles three protocol layers:
//   - OB responses: base64 + XOR encoded server responses from the PX collector
//   - Sensor payloads: XOR + base64 + shuffle-interleaved sensor POST data
//   - OBS payloads: AES-256-GCM encrypted Observer/SNR telemetry
//
// This package is decode/decrypt only — for traffic analysis and research.
package unobpx

import (
	"encoding/base64"
	"strings"
)

// Commands maps command-type labels to their parameter values.
// Labels are binary-like strings (e.g., "oo1o11", "o1111o") that vary
// across PX tag versions. Use [AutoMapCommands] to identify roles
// by value patterns instead of relying on fixed labels.
type Commands map[string][]string

// DecodeOB decodes a PX collector "ob" response field.
//
// The OB wire format is: base64(XOR(plaintext, key)).
// The XOR key is derived from the PX tag string — use [ComputeOBXORKey]
// to compute it from any tag, or extract it from init.js.
func DecodeOB(ob string, xorKey byte) string {
	// Fix base64 padding
	if rem := len(ob) % 4; rem > 0 {
		ob += strings.Repeat("=", 4-rem)
	}
	raw, err := base64.StdEncoding.DecodeString(ob)
	if err != nil {
		return ""
	}
	out := make([]byte, len(raw))
	for i, b := range raw {
		out[i] = b ^ xorKey
	}
	return string(out)
}

// ParseCommands splits decoded OB text into a command map.
//
// OB format uses "~~~~" as command separator and "|" as field separator.
// The first field of each command is the type label; remaining fields are parameters.
//
// Example decoded OB:
//
//	oo1o11|_px3|172800|<cookie_value>|false|500~~~~o1111o|<uuid>~~~~ooo11o|cu
func ParseCommands(decoded string) Commands {
	cmds := make(Commands)
	if !strings.Contains(decoded, "|") {
		return cmds
	}
	for _, raw := range strings.Split(decoded, "~~~~") {
		parts := strings.Split(raw, "|")
		if len(parts) == 0 {
			continue
		}
		cmds[parts[0]] = parts[1:]
	}
	return cmds
}

// ExtractCookies pulls _px* cookie name=value pairs from decoded OB text.
//
// Cookie commands have the format: <label>|<name>|<maxAge>|<value>|<secure>|<maxAge2>
// Only cookies with names starting with "_px" are returned.
func ExtractCookies(decoded string) map[string]string {
	cookies := make(map[string]string)
	if !strings.Contains(decoded, "|") {
		return cookies
	}
	for _, raw := range strings.Split(decoded, "~~~~") {
		parts := strings.Split(raw, "|")
		if len(parts) < 4 {
			continue
		}
		name := parts[1]
		value := parts[3]
		if strings.HasPrefix(name, "_px") {
			cookies[name] = value
		}
	}
	return cookies
}
