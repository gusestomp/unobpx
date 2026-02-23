package unobpx

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"strings"
)

// OBS (Observer/SNR) payloads are encrypted with AES-256-GCM.
// Wire format: "KAUHEVKF" + base64(nonce[12] + ciphertext + tag[16])

var (
	// obsAESKey is the hard-coded AES-256-GCM key used by PX's snr.js
	// for encrypting Observer telemetry payloads. This key is embedded
	// in the snr.js script and is the same across all PX-protected sites.
	obsAESKey = []byte("abC3UuT0Yte5FBGN2F6cQu0pegMgCMpr")

	// obsPrefix is the wire format identifier prepended to all OBS payloads.
	obsPrefix = "KAUHEVKF"
)

// DecryptOBS decrypts a PX Observer (SNR) payload.
//
// OBS payloads carry browser telemetry (fingerprints, timing, behavior data)
// and are sent to the /si/<token>/obs endpoint. The wire format is:
//
//	"KAUHEVKF" + base64(nonce[12] + ciphertext + GCM_tag[16])
//
// The returned string is the decrypted JSON containing the telemetry data.
func DecryptOBS(wireData string) (string, error) {
	if !strings.HasPrefix(wireData, obsPrefix) {
		return "", fmt.Errorf("expected OBS prefix %q", obsPrefix)
	}
	raw, err := base64.StdEncoding.DecodeString(wireData[len(obsPrefix):])
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}
	if len(raw) < 12 {
		return "", fmt.Errorf("data too short (%d bytes, need at least 12 for nonce)", len(raw))
	}
	nonce := raw[:12]
	ciphertext := raw[12:]

	block, err := aes.NewCipher(obsAESKey)
	if err != nil {
		return "", fmt.Errorf("AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("GCM: %w", err)
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("GCM decrypt: %w", err)
	}
	return string(plain), nil
}

// OBSAESKey returns the hard-coded AES-256-GCM key used for OBS encryption.
// This is provided for reference and external tooling.
func OBSAESKey() []byte {
	k := make([]byte, len(obsAESKey))
	copy(k, obsAESKey)
	return k
}
