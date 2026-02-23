package unobpx

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestDecryptOBS_RoundTrip(t *testing.T) {
	plaintext := `{"test":"observer_data","timestamp":1771836032025}`

	// Encrypt with the known key
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	block, err := aes.NewCipher(OBSAESKey())
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	combined := append(nonce, ciphertext...)
	wireData := "KAUHEVKF" + base64.StdEncoding.EncodeToString(combined)

	// Decrypt
	decrypted, err := DecryptOBS(wireData)
	if err != nil {
		t.Fatalf("DecryptOBS error: %v", err)
	}
	if decrypted != plaintext {
		t.Fatalf("DecryptOBS mismatch.\nExpected: %s\nGot:      %s", plaintext, decrypted)
	}
}

func TestDecryptOBS_BadPrefix(t *testing.T) {
	_, err := DecryptOBS("BADPREFIX" + "data")
	if err == nil {
		t.Fatal("Expected error for bad prefix")
	}
}

func TestOBSAESKey(t *testing.T) {
	key := OBSAESKey()
	if len(key) != 32 {
		t.Fatalf("Expected 32-byte key, got %d", len(key))
	}
	expected := "abC3UuT0Yte5FBGN2F6cQu0pegMgCMpr"
	if string(key) != expected {
		t.Fatalf("Key mismatch.\nExpected: %s\nGot:      %s", expected, string(key))
	}
}
