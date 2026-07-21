package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	}, strings.NewReader(""), &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run exit = %d, want 1; stderr: %s", code, stderr.String())
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "Could not safely prepare the local output file.") {
		t.Fatalf("output safety validation did not stop before claim: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestReceiveChecksDefaultOutputBeforeClaiming(t *testing.T) {
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
	if err := os.WriteFile(defaultReceiveFile, []byte("already here"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"receive",
		"https://zk-relay.example/a/abcdefghijklmnopqrstuv#v1." + vector.Key + "." + vector.Key,
	}, strings.NewReader(""), &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run exit = %d, want 1; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "Could not safely prepare the local output file.") {
		t.Fatalf("default output was not validated before claim: stderr=%q", stderr.String())
	}
}

func TestParseRelayURLAcceptsHumanPath(t *testing.T) {
	vector := loadVector(t)
	cap, err := parseRelayURL("https://zk-relay.example/h/abcdefghijklmnopqrstuv#v1." + vector.Key + "." + vector.Key)
	if err != nil {
		t.Fatal(err)
	}
	defer zero(cap.key)
	defer zero(cap.token)
	if cap.id != "abcdefghijklmnopqrstuv" {
		t.Fatalf("id = %q", cap.id)
	}
}

func TestAllowedRelaySchemeLocalhostHTTP(t *testing.T) {
	for _, raw := range []string{"http://127.0.0.1:8787", "http://localhost:8787", "https://zkr.example"} {
		parsed, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if !allowedRelayScheme(parsed) {
			t.Fatalf("allowedRelayScheme(%q) = false", raw)
		}
	}
	parsed, _ := url.Parse("http://evil.example")
	if allowedRelayScheme(parsed) {
		t.Fatal("http non-localhost should be refused")
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

func TestEncryptRoundTripMatchesDecrypt(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	nonce := bytes.Repeat([]byte{9}, 12)
	env := envelope{
		V:         1,
		Kind:      "text",
		Name:      "secret.txt",
		MediaType: "text/plain; charset=utf-8",
		Data:      base64.RawURLEncoding.EncodeToString([]byte("round-trip-secret")),
	}
	ciphertext, err := encryptEnvelope(env, key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	plain, decoded, err := decryptContainer(encryptedContainer{
		V:          1,
		Ciphertext: base64.RawURLEncoding.EncodeToString(ciphertext),
		Nonce:      base64.RawURLEncoding.EncodeToString(nonce),
		AAD:        protocolAAD,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	defer zero(plain)
	if decoded != env {
		t.Fatalf("envelope mismatch: %#v", decoded)
	}
	if string(plain) != "round-trip-secret" {
		t.Fatalf("plaintext = %q", plain)
	}
}

func TestEncryptMatchesBrowserTestVector(t *testing.T) {
	vector := loadVector(t)
	key, err := base64.RawURLEncoding.DecodeString(vector.Key)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := base64.RawURLEncoding.DecodeString(vector.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := encryptEnvelope(vector.Envelope, key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if got := base64.RawURLEncoding.EncodeToString(ciphertext); got != vector.Ciphertext {
		t.Fatalf("ciphertext mismatch\ngot  %s\nwant %s", got, vector.Ciphertext)
	}
}

func TestCreateRefusesSecretAsArgument(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"create", "--stdin", "leaked-secret"}, strings.NewReader("unused"), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "never as an argument") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestCreatePrintsPlainEnglishRecord(t *testing.T) {
	server := newCreateTestServer(t, createResponse{V: 1, ID: "abcdefghijklmnopqrstuvwx", ExpiresAt: "2030-01-01T00:00:00.000Z"})
	defer server.Close()

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"create",
		"--stdin",
		"--ttl", "1h",
		"--expire-after-reveal",
		"--origin", server.URL,
	}, strings.NewReader("piped-secret"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d stderr=%q", code, stderr.String())
	}
	out := stdout.String()
	for _, needle := range []string{
		"Created: yes",
		"State: available",
		"Expires: 2030-01-01T00:00:00.000Z",
		"Consumes on reveal: yes",
		"Agent link: " + server.URL + "/a/abcdefghijklmnopqrstuvwx#v1.",
		"Human link: " + server.URL + "/h/abcdefghijklmnopqrstuvwx#v1.",
		"Recipient: " + recipientOnce,
	} {
		if !strings.Contains(out, needle) {
			t.Fatalf("missing %q in %q", needle, out)
		}
	}
}

func TestCreateRecipientMatchesConsumeSemantics(t *testing.T) {
	server := newCreateTestServer(t, createResponse{V: 1, ID: "abcdefghijklmnopqrstuvwx", ExpiresAt: "2030-01-01T00:00:00.000Z"})
	defer server.Close()
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"create", "--stdin", "--ttl", "1h", "--expire-after-reveal=false", "--origin", server.URL,
	}, strings.NewReader("keep-alive"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d stderr=%q", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "Consumes on reveal: no") || !strings.Contains(out, recipientUntilExpiry) {
		t.Fatalf("stdout = %q", out)
	}
	if strings.Contains(out, recipientOnce) {
		t.Fatalf("oneshot recipient leaked into multi-reveal create: %q", out)
	}
}

func TestStatusLinkStdinExitCodes(t *testing.T) {
	available := newStatusTestServer(t, http.StatusOK, safeStatus{
		V: 1, State: "available", ExpiresAt: "2030-01-01T00:00:00.000Z", ExpireAfterReveal: true,
	})
	defer available.Close()
	vector := loadVector(t)
	link := available.URL + "/a/abcdefghijklmnopqrstuv#v1." + vector.Key + "." + vector.Key

	var stdout, stderr bytes.Buffer
	code := run([]string{"status", "--link-stdin"}, strings.NewReader(link+"\n"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("available exit = %d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "State: available") || !strings.Contains(stdout.String(), "Consumes on reveal: yes") {
		t.Fatalf("stdout = %q", stdout.String())
	}

	gone := newStatusTestServer(t, http.StatusGone, safeStatus{V: 1, State: "unavailable"})
	defer gone.Close()
	goneLink := gone.URL + "/a/abcdefghijklmnopqrstuv#v1." + vector.Key + "." + vector.Key
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"status", "--link", goneLink}, strings.NewReader(""), &stdout, &stderr)
	if code != 3 {
		t.Fatalf("gone exit = %d want 3 stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "State: unavailable") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestReceiveAcceptsLinkStdin(t *testing.T) {
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
	link := "https://zk-relay.example/a/abcdefghijklmnopqrstuv#v1." + vector.Key + "." + vector.Key
	var stdout, stderr bytes.Buffer
	code := run([]string{"receive", "--link-stdin", "--output", "existing"}, strings.NewReader(link), &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run exit = %d, want 1; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "Could not safely prepare the local output file.") {
		t.Fatalf("stderr = %q", stderr.String())
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

func newCreateTestServer(t *testing.T, created createResponse) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/api/v1/secrets" {
			http.NotFound(writer, request)
			return
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			http.Error(writer, "bad body", http.StatusBadRequest)
			return
		}
		var payload createRequest
		if err := json.Unmarshal(body, &payload); err != nil || payload.V != 1 || payload.Ciphertext == "" || payload.Nonce == "" || payload.AccessTokenHash == "" {
			http.Error(writer, "invalid", http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(writer).Encode(created)
	}))
}

func newStatusTestServer(t *testing.T, statusCode int, status safeStatus) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || !strings.HasSuffix(request.URL.Path, "/status") {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(statusCode)
		_ = json.NewEncoder(writer).Encode(status)
	}))
}
