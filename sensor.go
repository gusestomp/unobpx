package unobpx

import (
	"encoding/base64"
	"math"
	"sort"
	"strings"
)

// DecodeSensor decodes a PX sensor payload captured from network traffic.
//
// PX sensor payloads (the "payload" POST parameter) are obfuscated with:
//  1. XOR each byte of the raw JSON with key 50
//  2. Base64 encode
//  3. Derive a shuffle key from STS (server timestamp string)
//  4. Interleave shuffle key characters at computed positions
//
// To decode, you need the encoded payload string plus the UUID and STS
// values, both visible as separate POST parameters in the same request.
//
// Returns the decoded JSON string.
func DecodeSensor(encoded, uuid, sts string) (string, error) {
	if sts == "" {
		sts = "1604064986000"
	}

	// Derive shuffle key from STS
	key := xorString(b64Encode(sts), 10)
	keyLen := len(key)

	// Compute shuffle indices
	indices := computeIndices(key, len(encoded)-keyLen, uuid)

	// Remove interleaved key characters (work backwards to preserve indices)
	removePositions := make([]int, keyLen)
	for i := 0; i < keyLen; i++ {
		removePositions[i] = indices[i] - 1
	}
	sort.Sort(sort.Reverse(sort.IntSlice(removePositions)))

	chars := []byte(encoded)
	for _, pos := range removePositions {
		if pos >= 0 && pos < len(chars) {
			chars = append(chars[:pos], chars[pos+1:]...)
		}
	}
	b64Payload := string(chars)

	// Base64 decode, then XOR with 50 to recover the original JSON
	decoded, err := b64Decode(b64Payload)
	if err != nil {
		decoded, err = b64DecodeLenient(b64Payload)
		if err != nil {
			return "", err
		}
	}
	return xorString(decoded, 50), nil
}

// xorString XORs each byte of s with key.
func xorString(s string, key byte) string {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		out[i] = s[i] ^ key
	}
	return string(out)
}

func b64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func b64Decode(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// b64DecodeLenient strips non-base64 chars before decoding.
// The STS-derived shuffle key contains chars outside the base64 alphabet
// (^, }, >, etc.). After index-based removal, some may remain.
func b64DecodeLenient(s string) (string, error) {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' {
			b.WriteByte(c)
		}
	}
	clean := b.String()
	if r := len(clean) % 4; r != 0 {
		clean += strings.Repeat("=", 4-r)
	}
	decoded, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

func linearMap(value, inMin, inMax, outMin, outMax float64) int {
	return int(math.Floor(((value - inMin) / (inMax - inMin)) * (outMax - outMin) + outMin))
}

// computeIndices computes the deterministic shuffle positions.
// The algorithm builds a matrix from XOR(base64(UUID), 10), then
// computes position = r[col] * r[row] for each key character index.
func computeIndices(keyStr string, payloadLen int, uuid string) []int {
	r := xorString(b64Encode(uuid), 10)

	// Pass 1: find max product for linear mapping
	maxVal := -1
	for i := 0; i < len(keyStr); i++ {
		row := i/len(r) + 1
		col := i % len(r)
		product := int(r[col]) * int(r[row])
		if product > maxVal {
			maxVal = product
		}
	}

	// Pass 2: compute positions with collision resolution
	positions := make([]int, 0, len(keyStr))
	for i := 0; i < len(keyStr); i++ {
		row := i/len(r) + 1
		col := i % len(r)
		pos := int(r[col]) * int(r[row])

		if pos >= payloadLen {
			pos = linearMap(float64(pos), 0, float64(maxVal), 0, float64(payloadLen-1))
		}

		for containsInt(positions, pos) {
			pos++
		}
		positions = append(positions, pos)
	}

	sorted := make([]int, len(positions))
	copy(sorted, positions)
	sort.Ints(sorted)
	return sorted
}

func containsInt(s []int, v int) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
