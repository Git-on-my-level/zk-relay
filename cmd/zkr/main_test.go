package main

import (
	"bytes"
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
	if string(plain) != "zk-relay-interoperability" {
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
	cap, err := parseRelayURL("https://zk-relay.example/a/abcdefghijklmnopqrstuv#v1." + vector.Key + "." + vector.Key)
	if err != nil {
		t.Fatal(err)
	}
	defer zero(cap.key)
	defer zero(cap.token)
	if cap.endpoint != "https://zk-relay.example" || strings.Contains(cap.endpoint, "#") {
		t.Fatalf("unsafe endpoint: %q", cap.endpoint)
	}
}

func TestParseRelayURLRequiresHTTPSWithoutAmbiguousURLParts(t *testing.T) {
	vector := loadVector(t)
	fragment := "#v1." + vector.Key + "." + vector.Key
	for _, raw := range []string{
		"http://zk-relay.example/a/abcdefghijklmnopqrstuv" + fragment,
		"https://zk-relay.example/a/abcdefghijklmnopqrstuv?tracking=value" + fragment,
		"https://user@zk-relay.example/a/abcdefghijklmnopqrstuv" + fragment,
	} {
		if _, err := parseRelayURL(raw); err == nil {
			t.Fatalf("parseRelayURL(%q) unexpectedly succeeded", raw)
		}
	}
}

func TestDecodeJSONAcceptsMaximumEncryptedContainerResponse(t *testing.T) {
	encodedCiphertext := strings.Repeat("A", base64.RawURLEncoding.EncodedLen(maxContainerBytes))
	document, err := json.Marshal(encryptedContainer{
		V:          1,
		Ciphertext: encodedCiphertext,
		Nonce:      "EBESExQVFhcYGRob",
		AAD:        protocolAAD,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(document) > maxResponseBytes {
		t.Fatalf("maximum response is %d bytes, limit is %d", len(document), maxResponseBytes)
	}
	var decoded encryptedContainer
	if err := decodeJSON(strings.NewReader(string(document)), &decoded); err != nil {
		t.Fatalf("decodeJSON rejected a maximum-size response: %v", err)
	}
	if decoded.Ciphertext != encodedCiphertext {
		t.Fatal("ciphertext changed while decoding")
	}
}

func TestReceiveChecksExplicitOutputBeforeClaiming(t *testing.T) {
	vector := loadVector(t)
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	temporary := t.TempDir()
	if err := os.Chdir(temporary); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(original) })
	if err := os.WriteFile("existing", []byte("already here"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"receive",
		"https://zk-relay.example/a/abcdefghijklmnopqrstuv#v1." + vector.Key + "." + vector.Key,
		"--output", "existing",
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run exit = %d, want 1; stderr: %s", code, stderr.String())
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "Could not safely prepare the local output file.") {
		t.Fatalf("output safety validation did not stop before claim: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestWriteBundleSavesItemsIntoDirectory(t *testing.T) {
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	temporary := t.TempDir()
	if err := os.Chdir(temporary); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(original) })

	payload, err := json.Marshal(bundlePayload{Items: []bundleItem{
		{Kind: "text", Name: "secret.txt", MediaType: "text/plain; charset=utf-8", Data: base64.RawURLEncoding.EncodeToString([]byte("note"))},
		{Kind: "file", Name: "blob.bin", MediaType: "application/octet-stream", Data: base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3})},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeBundle("out", payload, false); err != nil {
		t.Fatal(err)
	}
	text, err := os.ReadFile(filepath.Join("out", "secret.txt"))
	if err != nil || string(text) != "note" {
		t.Fatalf("text item = %q err=%v", text, err)
	}
	file, err := os.ReadFile(filepath.Join("out", "blob.bin"))
	if err != nil || !bytes.Equal(file, []byte{1, 2, 3}) {
		t.Fatalf("file item = %v err=%v", file, err)
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
