package unobpx

import (
	"encoding/base64"
	"testing"
)

func TestDecodeOB_RoundTrip(t *testing.T) {
	original := "oo1o11|_px3|172800|cookie_value|false|500~~~~o1111o|abc12345-1234-1234-1234-123456789012~~~~ooo11o|cu"
	var xorKey byte = 66

	// Encode: XOR then base64
	xored := make([]byte, len(original))
	for i, b := range []byte(original) {
		xored[i] = b ^ xorKey
	}
	encoded := base64.StdEncoding.EncodeToString(xored)

	decoded := DecodeOB(encoded, xorKey)
	if decoded != original {
		t.Fatalf("DecodeOB round-trip failed.\nExpected: %s\nGot:      %s", original, decoded)
	}
}

func TestDecodeOB_PaddingFix(t *testing.T) {
	// Test that base64 padding is auto-fixed
	original := "test"
	var xorKey byte = 42

	xored := make([]byte, len(original))
	for i, b := range []byte(original) {
		xored[i] = b ^ xorKey
	}
	encoded := base64.StdEncoding.EncodeToString(xored)
	// Strip padding
	encoded = encoded[:len(encoded)-2]

	decoded := DecodeOB(encoded, xorKey)
	if decoded != original {
		t.Fatalf("DecodeOB with stripped padding failed.\nExpected: %s\nGot:      %s", original, decoded)
	}
}

func TestParseCommands(t *testing.T) {
	decoded := "oo1o11|_px3|172800|val|false|500~~~~o1111o|abc12345-1234-1234-1234-123456789012~~~~ooo11o|cu"
	cmds := ParseCommands(decoded)

	if len(cmds) != 3 {
		t.Fatalf("Expected 3 commands, got %d", len(cmds))
	}

	if data, ok := cmds["oo1o11"]; !ok || data[0] != "_px3" {
		t.Errorf("Missing or wrong cookie command: %v", data)
	}
	if data, ok := cmds["o1111o"]; !ok || data[0] != "abc12345-1234-1234-1234-123456789012" {
		t.Errorf("Missing or wrong SID command: %v", data)
	}
	if data, ok := cmds["ooo11o"]; !ok || data[0] != "cu" {
		t.Errorf("Missing or wrong mode command: %v", data)
	}
}

func TestExtractCookies(t *testing.T) {
	decoded := "oo1o11|_px3|300|cookie_value_px3|true|300~~~~oo1o11|_pxde|600|cookie_value_pxde|true|600~~~~o1111o|not_a_cookie|value"
	cookies := ExtractCookies(decoded)

	if cookies["_px3"] != "cookie_value_px3" {
		t.Errorf("_px3: expected cookie_value_px3, got %q", cookies["_px3"])
	}
	if cookies["_pxde"] != "cookie_value_pxde" {
		t.Errorf("_pxde: expected cookie_value_pxde, got %q", cookies["_pxde"])
	}
	if _, ok := cookies["not_a_cookie"]; ok {
		t.Error("Should not extract non-_px cookies")
	}
}

func TestAutoMapCommands(t *testing.T) {
	// Build a realistic decoded OB with known patterns
	decoded := "" +
		"abc123|deadbeef-1234-5678-9abc-def012345678~~~~" + // SID (1 UUID)
		"def456|cafebabe-1234-5678-9abc-def012345678|31536000|false~~~~" + // VID (UUID + TTL + false)
		"ghi789|feedface-1234-5678-9abc-def012345678|false~~~~" + // CTS (UUID + false)
		"jkl012|" + "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789" + "~~~~" + // CS (64-char hex)
		"mno345|1771836032025~~~~" + // Timestamp (13 digits)
		"pqr678|5665~~~~" + // CLS (4 digits)
		"stu901|d6e1505n9b0s73efc7dg~~~~" + // Token (20 char alnum)
		"vwx234|cu~~~~" + // CS mode
		"yza567|_px3|172800|some_cookie_value|false|500" // Cookie

	roles := AutoMapCommands(decoded)

	tests := map[string]string{
		RoleSID:       "abc123",
		RoleVID:       "def456",
		RoleCTS:       "ghi789",
		RoleCS:        "jkl012",
		RoleTimestamp: "mno345",
		RoleCLS:       "pqr678",
		RoleToken:     "stu901",
		RoleCSMode:    "vwx234",
		RoleCookie:    "yza567",
	}

	for role, expectedLabel := range tests {
		if got, ok := roles[role]; !ok {
			t.Errorf("Role %q not detected", role)
		} else if got != expectedLabel {
			t.Errorf("Role %q: expected label %q, got %q", role, expectedLabel, got)
		}
	}
}
