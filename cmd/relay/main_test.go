package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type testVector struct {
	V          int      `json:"v"`
	AAD        string   `json:"aad"`
	Key        string   `json:"key"`
	Nonce      string   `json:"nonce"`
	Envelope   envelope `json:"envelope"`
	Ciphertext string   `json:"ciphertext"`
}

func loadVector(t *testing.T) testVector {
	t.Helper()
	bytes, err := os.ReadFile(filepath.Join("..", "..", "protocol", "test-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector testVector
	if err := json.Unmarshal(bytes, &vector); err != nil {
		t.Fatal(err)
	}
	return vector
}

func TestReceiverDecryptsBrowserVector(t *testing.T) {
	vector := loadVector(t)
	key, err := base64.RawURLEncoding.DecodeString(vector.Key)
	if err != nil {
		t.Fatal(err)
	}
	plain, decoded, err := decryptContainer(encryptedContainer{V: vector.V, Ciphertext: vector.Ciphertext, Nonce: vector.Nonce, AAD: vector.AAD}, key)
	if err != nil {
		t.Fatal(err)
	}
	defer zero(plain)
	if decoded != vector.Envelope {
		t.Fatalf("envelope mismatch: %#v", decoded)
	}
	if string(plain) != "relay-interoperability" {
		t.Fatalf("unexpected plaintext: %q", plain)
	}
}

func TestReceiverRejectsModifiedCiphertext(t *testing.T) {
	vector := loadVector(t)
	key, _ := base64.RawURLEncoding.DecodeString(vector.Key)
	modified := vector.Ciphertext[:len(vector.Ciphertext)-1] + "A"
	if _, _, err := decryptContainer(encryptedContainer{V: 1, Ciphertext: modified, Nonce: vector.Nonce, AAD: vector.AAD}, key); err == nil {
		t.Fatal("expected authentication failure")
	}
}

func TestParseRelayURLKeepsCapabilitiesOutOfEndpoint(t *testing.T) {
	vector := loadVector(t)
	cap, err := parseRelayURL("https://relay.example/a/abcdefghijklmnopqrstuv#v1." + vector.Key + "." + vector.Key)
	if err != nil {
		t.Fatal(err)
	}
	defer zero(cap.key)
	defer zero(cap.token)
	if cap.endpoint != "https://relay.example" || strings.Contains(cap.endpoint, "#") {
		t.Fatalf("unsafe endpoint: %q", cap.endpoint)
	}
}

func TestFilenameSanitization(t *testing.T) {
	for input, want := range map[string]string{
		"../../.secret": "secret",
		"con":           "secret",
		"report.txt":    "report.txt",
		"bad\x00name":   "bad-name",
	} {
		if got := sanitizeFilename(input); got != want {
			t.Errorf("sanitizeFilename(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestSecureOutputRefusesOverwriteAndSymlinkParent(t *testing.T) {
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	temporary := t.TempDir()
	if err := os.Chdir(temporary); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(original) })
	data := []byte("test")
	if err := writeSecureFile("secret", data, false); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat("secret")
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
	if err := writeSecureFile("secret", data, false); err == nil {
		t.Fatal("expected no-overwrite refusal")
	}
	if err := os.Symlink(".", "linked"); err == nil {
		if err := writeSecureFile(filepath.Join("linked", "secret"), data, false); err == nil {
			t.Fatal("expected symlink parent refusal")
		}
	}
}
