package unobpx

import "testing"

func TestDecodeSensor_KnownPayload(t *testing.T) {
	// Test the internal helpers work correctly
	original := `{"test":"hello","value":42}`
	uuid := "12345678-1234-1234-1234-123456789012"
	sts := "1771836032025"

	// Manually encode: XOR with 50, base64, then interleave
	xored := xorString(original, 50)
	b64 := b64Encode(xored)

	key := xorString(b64Encode(sts), 10)
	indices := computeIndices(key, len(b64), uuid)

	// Interleave key chars
	result := make([]byte, 0, len(b64)+len(key))
	offset := 0
	for i := 0; i < len(key); i++ {
		end := indices[i] - i - 1
		result = append(result, b64[offset:end]...)
		result = append(result, key[i])
		offset = end
	}
	result = append(result, b64[offset:]...)
	encoded := string(result)

	// Decode
	decoded, err := DecodeSensor(encoded, uuid, sts)
	if err != nil {
		t.Fatalf("DecodeSensor error: %v", err)
	}
	if decoded != original {
		t.Fatalf("DecodeSensor mismatch.\nExpected: %s\nGot:      %s", original, decoded)
	}
}

func TestComputeOBXORKey(t *testing.T) {
	tests := []struct {
		tag  string
		want byte
	}{
		{"Zj4TeyhNFxB5", 66},     // Known Walmart tag
		{"IUMUAGcoCHQlTA==", 62}, // Known Skyscanner tag
	}

	for _, tt := range tests {
		got := ComputeOBXORKey(tt.tag)
		if got != tt.want {
			t.Errorf("ComputeOBXORKey(%q) = %d, want %d", tt.tag, got, tt.want)
		}
	}
}
