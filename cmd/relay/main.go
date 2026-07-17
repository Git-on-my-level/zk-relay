package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

const (
	protocolAAD       = "relay/v1;envelope"
	maxContainerBytes = 1_500_000
)

type capability struct {
	endpoint  string
	id        string
	key       []byte
	token     []byte
	tokenText string
}

type safeStatus struct {
	V                 int    `json:"v"`
	State             string `json:"state"`
	ExpiresAt         string `json:"expiresAt"`
	ExpireAfterReveal bool   `json:"expireAfterReveal"`
}

type encryptedContainer struct {
	V          int    `json:"v"`
	Ciphertext string `json:"ciphertext"`
	Nonce      string `json:"nonce"`
	AAD        string `json:"aad"`
}

type envelope struct {
	V         int    `json:"v"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	MediaType string `json:"mediaType"`
	Data      string `json:"data"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "receive" {
		fmt.Fprintln(stderr, "Usage: relay receive \"$RELAY_URL\" --output ./secret")
		return 2
	}
	if len(args) < 2 {
		fmt.Fprintln(stderr, "A complete Relay URL is required.")
		return 2
	}

	flags := flag.NewFlagSet("receive", flag.ContinueOnError)
	flags.SetOutput(stderr)
	output := flags.String("output", "", "local output path")
	force := flags.Bool("force", false, "allow replacing an existing regular file")
	plainStdout := flags.Bool("stdout", false, "write plaintext to stdout")
	allowPlainStdout := flags.Bool("allow-plaintext-stdout", false, "acknowledge transcript risk")
	if err := flags.Parse(args[2:]); err != nil {
		return 2
	}
	if *plainStdout && !*allowPlainStdout {
		fmt.Fprintln(stderr, "Refusing plaintext stdout. Repeat with --stdout --allow-plaintext-stdout after considering transcript risk.")
		return 2
	}
	if !*plainStdout && flags.NArg() != 0 {
		fmt.Fprintln(stderr, "Unexpected arguments after receive options.")
		return 2
	}

	cap, err := parseRelayURL(args[1])
	if err != nil {
		fmt.Fprintln(stderr, "The Relay URL is invalid.")
		return 2
	}
	defer zero(cap.key)
	defer zero(cap.token)

	client := &http.Client{
		Timeout: 20 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("redirects are not accepted")
		},
	}
	status, err := fetchStatus(client, cap)
	if err != nil || status.State != "available" {
		fmt.Fprintln(stderr, "The secret is no longer available.")
		return 1
	}
	if status.ExpireAfterReveal {
		fmt.Fprintln(stderr, "Retrieving this secret will make the link stop working.")
	} else {
		fmt.Fprintln(stderr, "Retrieving this secret will leave it available until it expires.")
	}

	container, err := claim(client, cap)
	if err != nil {
		fmt.Fprintln(stderr, "The secret is no longer available.")
		return 1
	}
	plain, decodedEnvelope, err := decryptContainer(container, cap.key)
	if err != nil {
		fmt.Fprintln(stderr, "The encrypted content could not be authenticated.")
		return 1
	}
	defer zero(plain)
	if decodedEnvelope.Kind != "text" && decodedEnvelope.Kind != "file" {
		fmt.Fprintln(stderr, "The encrypted envelope is invalid.")
		return 1
	}

	if *plainStdout {
		fmt.Fprintln(stderr, "Warning: plaintext will now be written to stdout and may enter an agent transcript or shell history.")
		if _, err := stdout.Write(plain); err != nil {
			fmt.Fprintln(stderr, "Could not write plaintext to stdout.")
			return 1
		}
		return 0
	}

	destination := *output
	if destination == "" {
		destination = filepath.Join(".", sanitizeFilename(decodedEnvelope.Name))
	}
	if err := writeSecureFile(destination, plain, *force); err != nil {
		fmt.Fprintln(stderr, "Could not safely write the local output file.")
		return 1
	}
	fmt.Fprintln(stderr, "Saved decrypted value to a local file.")
	return 0
}

func parseRelayURL(raw string) (capability, error) {
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
		return capability{}, errors.New("invalid URL")
	}
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(parts) != 2 || parts[0] != "a" || !validIdentifier(parts[1]) {
		return capability{}, errors.New("invalid agent path")
	}
	fragment := strings.Split(parsed.Fragment, ".")
	if len(fragment) != 3 || fragment[0] != "v1" {
		return capability{}, errors.New("invalid fragment")
	}
	key, err := base64.RawURLEncoding.DecodeString(fragment[1])
	if err != nil || len(key) != 32 {
		return capability{}, errors.New("invalid key")
	}
	token, err := base64.RawURLEncoding.DecodeString(fragment[2])
	if err != nil || len(token) != 32 {
		zero(key)
		return capability{}, errors.New("invalid token")
	}
	return capability{endpoint: parsed.Scheme + "://" + parsed.Host, id: parts[1], key: key, token: token, tokenText: fragment[2]}, nil
}

func validIdentifier(value string) bool {
	if len(value) < 22 {
		return false
	}
	for _, runeValue := range value {
		if !(runeValue >= 'a' && runeValue <= 'z') && !(runeValue >= 'A' && runeValue <= 'Z') && !(runeValue >= '0' && runeValue <= '9') && runeValue != '-' && runeValue != '_' {
			return false
		}
	}
	return true
}

func fetchStatus(client *http.Client, cap capability) (safeStatus, error) {
	request, err := http.NewRequest(http.MethodGet, cap.endpoint+"/api/v1/secrets/"+cap.id+"/status", nil)
	if err != nil {
		return safeStatus{}, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return safeStatus{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return safeStatus{}, errors.New("unavailable")
	}
	var status safeStatus
	if err := decodeJSON(response.Body, &status); err != nil {
		return safeStatus{}, err
	}
	return status, nil
}

func claim(client *http.Client, cap capability) (encryptedContainer, error) {
	request, err := http.NewRequest(http.MethodPost, cap.endpoint+"/api/v1/secrets/"+cap.id+"/reveal", nil)
	if err != nil {
		return encryptedContainer{}, err
	}
	request.Header.Set("Authorization", "Relay "+cap.tokenText)
	request.Header.Set("Accept", "application/vnd.relay.encrypted+json")
	response, err := client.Do(request)
	if err != nil {
		return encryptedContainer{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return encryptedContainer{}, errors.New("unavailable")
	}
	var container encryptedContainer
	if err := decodeJSON(response.Body, &container); err != nil {
		return encryptedContainer{}, err
	}
	return container, nil
}

func decodeJSON(reader io.Reader, destination any) error {
	limited := io.LimitReader(reader, maxContainerBytes+1024)
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	return decoder.Decode(destination)
}

func decryptContainer(container encryptedContainer, key []byte) ([]byte, envelope, error) {
	if container.V != 1 || container.AAD != protocolAAD || len(key) != 32 {
		return nil, envelope{}, errors.New("invalid encrypted container")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(container.Nonce)
	if err != nil || len(nonce) != 12 {
		return nil, envelope{}, errors.New("invalid nonce")
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(container.Ciphertext)
	if err != nil || len(ciphertext) == 0 || len(ciphertext) > maxContainerBytes {
		return nil, envelope{}, errors.New("invalid ciphertext")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, envelope{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, envelope{}, err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, []byte(protocolAAD))
	zero(ciphertext)
	if err != nil {
		return nil, envelope{}, errors.New("authentication failure")
	}
	var decoded envelope
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		zero(plain)
		return nil, envelope{}, errors.New("invalid envelope")
	}
	data, err := base64.RawURLEncoding.DecodeString(decoded.Data)
	if err != nil || len(data) > 1024*1024 {
		zero(plain)
		return nil, envelope{}, errors.New("invalid payload")
	}
	zero(plain)
	if decoded.V != 1 || (decoded.Kind != "text" && decoded.Kind != "file") || decoded.Name == "" || decoded.MediaType == "" {
		zero(data)
		return nil, envelope{}, errors.New("invalid envelope")
	}
	return data, decoded, nil
}

func sanitizeFilename(name string) string {
	name = filepath.Base(name)
	name = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || strings.ContainsRune(`\\/:*?"<>|`, r) {
			return '-'
		}
		return r
	}, name)
	name = strings.TrimLeft(name, ".")
	name = strings.TrimSpace(name)
	if len(name) > 120 {
		name = name[:120]
	}
	lower := strings.ToLower(name)
	stem := strings.Split(lower, ".")[0]
	reserved := stem == "con" || stem == "prn" || stem == "aux" || stem == "nul"
	for index := 1; index <= 9; index++ {
		reserved = reserved || stem == fmt.Sprintf("com%d", index) || stem == fmt.Sprintf("lpt%d", index)
	}
	if name == "" || reserved {
		return "secret"
	}
	return name
}

func writeSecureFile(destination string, data []byte, force bool) error {
	if filepath.IsAbs(destination) {
		return errors.New("absolute output paths are refused")
	}
	cleaned := filepath.Clean(destination)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return errors.New("unsafe output path")
	}
	parent := filepath.Dir(cleaned)
	if err := requireExistingRegularParent(parent); err != nil {
		return err
	}
	if info, err := os.Lstat(cleaned); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("output is not a regular file")
		}
		if !force {
			return errors.New("output exists")
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	temporary, err := os.CreateTemp(parent, ".relay-")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if force {
		return os.Rename(temporaryName, cleaned)
	}
	if err := os.Link(temporaryName, cleaned); err != nil {
		return err
	}
	return os.Remove(temporaryName)
}

func requireExistingRegularParent(parent string) error {
	if parent == "" {
		parent = "."
	}
	parts := strings.Split(filepath.Clean(parent), string(filepath.Separator))
	current := "."
	for _, part := range parts {
		if part == "." || part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("output parent is unsafe")
		}
	}
	return nil
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
