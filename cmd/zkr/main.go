package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
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
	protocolAAD            = "zk-relay/v1;envelope"
	bundleMediaType        = "application/vnd.zk-relay.bundle+json"
	maxPayloadBytes        = 1024 * 1024
	maxContainerBytes      = 1_450_000
	defaultOrigin          = "https://zkr.scalingforever.com"
	defaultReceiveFile     = "secret"
	defaultReceiveBundle   = "bundle"
	recipientOnce          = "Retrieve exactly once and pipe the bytes directly into the destination secret store. Do not print, log, hash, transform, or save the value."
	recipientUntilExpiry   = "Retrieve and pipe the bytes directly into the destination secret store. This link remains available until it expires. Do not print, log, hash, transform, or save the value."
)

var maxResponseBytes = base64.RawURLEncoding.EncodedLen(maxContainerBytes) + 1024

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

type bundleItem struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	MediaType string `json:"mediaType"`
	Data      string `json:"data"`
}

type bundlePayload struct {
	Items []bundleItem `json:"items"`
}

type createRequest struct {
	V                 int    `json:"v"`
	Ciphertext        string `json:"ciphertext"`
	Nonce             string `json:"nonce"`
	AccessTokenHash   string `json:"accessTokenHash"`
	ExpiresInSeconds  int    `json:"expiresInSeconds"`
	ExpireAfterReveal bool   `json:"expireAfterReveal"`
}

type createResponse struct {
	V         int    `json:"v"`
	ID        string `json:"id"`
	ExpiresAt string `json:"expiresAt"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}
	switch args[0] {
	case "create":
		return runCreate(args[1:], stdin, stdout, stderr)
	case "status":
		return runStatus(args[1:], stdin, stdout, stderr)
	case "receive":
		return runReceive(args[1:], stdin, stdout, stderr)
	default:
		printUsage(stderr)
		return 2
	}
}

func printUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "Usage:")
	fmt.Fprintln(stderr, "  zkr create --stdin|--file PATH [--ttl 1h|1d|7d] [--expire-after-reveal] [--origin URL]")
	fmt.Fprintln(stderr, "  zkr status --link-stdin|--link URL")
	fmt.Fprintln(stderr, "  zkr receive (--link-stdin|--link URL|URL) [--output PATH]")
}

func runCreate(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("create", flag.ContinueOnError)
	flags.SetOutput(stderr)
	useStdin := flags.Bool("stdin", false, "read secret bytes from stdin")
	filePath := flags.String("file", "", "read secret bytes from a file")
	ttl := flags.String("ttl", "1h", "expiry: 1h, 1d, or 7d")
	expireAfterReveal := flags.Bool("expire-after-reveal", true, "consume the secret after one successful reveal")
	origin := flags.String("origin", defaultOriginValue(), "ZK Relay origin")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "Unexpected arguments after create options. Pass the secret with --stdin or --file, never as an argument.")
		return 2
	}
	if *useStdin == (*filePath != "") {
		fmt.Fprintln(stderr, "Choose exactly one of --stdin or --file.")
		return 2
	}
	expiresInSeconds, err := parseTTL(*ttl)
	if err != nil {
		fmt.Fprintln(stderr, "TTL must be 1h, 1d, or 7d.")
		return 2
	}
	originURL, err := normalizeOrigin(*origin)
	if err != nil {
		fmt.Fprintln(stderr, "The --origin URL is invalid.")
		return 2
	}

	var payload []byte
	if *useStdin {
		payload, err = io.ReadAll(io.LimitReader(stdin, int64(maxPayloadBytes)+1))
	} else {
		payload, err = readSecretFile(*filePath)
	}
	if err != nil {
		fmt.Fprintln(stderr, "Could not read the secret.")
		return 1
	}
	defer zero(payload)
	if len(payload) == 0 || len(payload) > maxPayloadBytes {
		fmt.Fprintln(stderr, "Secret must be between 1 byte and 1 MiB.")
		return 2
	}

	key, err := randomBytes(32)
	if err != nil {
		fmt.Fprintln(stderr, "Could not generate encryption material.")
		return 1
	}
	defer zero(key)
	token, err := randomBytes(32)
	if err != nil {
		fmt.Fprintln(stderr, "Could not generate encryption material.")
		return 1
	}
	defer zero(token)
	nonce, err := randomBytes(12)
	if err != nil {
		fmt.Fprintln(stderr, "Could not generate encryption material.")
		return 1
	}
	defer zero(nonce)

	env := envelope{
		V:         1,
		Kind:      "text",
		Name:      "secret.txt",
		MediaType: "text/plain; charset=utf-8",
		Data:      base64.RawURLEncoding.EncodeToString(payload),
	}
	ciphertext, err := encryptEnvelope(env, key, nonce)
	if err != nil {
		fmt.Fprintln(stderr, "Could not encrypt the secret.")
		return 1
	}
	defer zero(ciphertext)

	body, err := json.Marshal(createRequest{
		V:                 1,
		Ciphertext:        base64.RawURLEncoding.EncodeToString(ciphertext),
		Nonce:             base64.RawURLEncoding.EncodeToString(nonce),
		AccessTokenHash:   hashAccessToken(token),
		ExpiresInSeconds:  expiresInSeconds,
		ExpireAfterReveal: *expireAfterReveal,
	})
	if err != nil {
		fmt.Fprintln(stderr, "Could not build the create request.")
		return 1
	}

	client := httpClient()
	request, err := http.NewRequest(http.MethodPost, originURL+"/api/v1/secrets", bytes.NewReader(body))
	if err != nil {
		fmt.Fprintln(stderr, "Could not build the create request.")
		return 1
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		fmt.Fprintln(stderr, "Could not create the secret.")
		return 1
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		fmt.Fprintln(stderr, "Could not create the secret.")
		return 1
	}
	var created createResponse
	if err := decodeJSON(response.Body, &created); err != nil || created.V != 1 || created.ID == "" || created.ExpiresAt == "" {
		fmt.Fprintln(stderr, "The create response was invalid.")
		return 1
	}
	if !validIdentifier(created.ID) {
		fmt.Fprintln(stderr, "The create response was invalid.")
		return 1
	}

	keyText := base64.RawURLEncoding.EncodeToString(key)
	tokenText := base64.RawURLEncoding.EncodeToString(token)
	agentLink := fmt.Sprintf("%s/a/%s#v1.%s.%s", originURL, created.ID, keyText, tokenText)
	humanLink := fmt.Sprintf("%s/h/%s#v1.%s.%s", originURL, created.ID, keyText, tokenText)
	consumes := "no"
	recipient := recipientUntilExpiry
	if *expireAfterReveal {
		consumes = "yes"
		recipient = recipientOnce
	}
	fmt.Fprintf(stdout, "Created: yes\nState: available\nExpires: %s\nConsumes on reveal: %s\nAgent link: %s\nHuman link: %s\n\nRecipient: %s\n",
		created.ExpiresAt, consumes, agentLink, humanLink, recipient)
	return 0
}

func runStatus(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("status", flag.ContinueOnError)
	flags.SetOutput(stderr)
	link := flags.String("link", "", "complete agent URL including fragment")
	linkStdin := flags.Bool("link-stdin", false, "read the agent URL from stdin")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "Unexpected arguments after status options.")
		return 2
	}
	raw, err := resolveLink(*link, *linkStdin, "", stdin)
	if err != nil {
		fmt.Fprintln(stderr, "Provide exactly one of --link or --link-stdin.")
		return 2
	}
	cap, err := parseRelayURL(raw)
	if err != nil {
		fmt.Fprintln(stderr, "The ZK Relay URL is invalid.")
		return 2
	}
	defer zero(cap.key)
	defer zero(cap.token)

	status, err := fetchStatus(httpClient(), cap)
	if err != nil || status.State != "available" {
		fmt.Fprintln(stdout, "State: unavailable")
		return 3
	}
	consumes := "no"
	if status.ExpireAfterReveal {
		consumes = "yes"
	}
	fmt.Fprintf(stdout, "State: available\nExpires: %s\nConsumes on reveal: %s\n", status.ExpiresAt, consumes)
	return 0
}

func runReceive(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	positional := ""
	flagArgs := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		positional = args[0]
		flagArgs = args[1:]
	}
	flags := flag.NewFlagSet("receive", flag.ContinueOnError)
	flags.SetOutput(stderr)
	output := flags.String("output", "", "local output path")
	force := flags.Bool("force", false, "allow replacing an existing regular file")
	plainStdout := flags.Bool("stdout", false, "write plaintext to stdout")
	allowPlainStdout := flags.Bool("allow-plaintext-stdout", false, "acknowledge transcript risk")
	link := flags.String("link", "", "complete agent URL including fragment")
	linkStdin := flags.Bool("link-stdin", false, "read the agent URL from stdin")
	if err := flags.Parse(flagArgs); err != nil {
		return 2
	}
	if *plainStdout && !*allowPlainStdout {
		fmt.Fprintln(stderr, "Refusing plaintext stdout. Repeat with --stdout --allow-plaintext-stdout after considering transcript risk.")
		return 2
	}
	if *plainStdout && *output != "" {
		fmt.Fprintln(stderr, "--stdout and --output cannot be used together.")
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "Unexpected arguments after receive options.")
		return 2
	}
	raw, err := resolveLink(*link, *linkStdin, positional, stdin)
	if err != nil {
		fmt.Fprintln(stderr, "Provide exactly one agent URL via argument, --link, or --link-stdin.")
		return 2
	}

	cap, err := parseRelayURL(raw)
	if err != nil {
		fmt.Fprintln(stderr, "The ZK Relay URL is invalid.")
		return 2
	}
	defer zero(cap.key)
	defer zero(cap.token)

	if !*plainStdout {
		if err := prepareReceiveOutput(*output, *force); err != nil {
			fmt.Fprintln(stderr, "Could not safely prepare the local output file.")
			return 1
		}
	}

	client := httpClient()
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
	if *plainStdout && status.ExpireAfterReveal {
		fmt.Fprintln(stderr, "Warning: --stdout cannot deliver bundles. A one-shot bundle share would be consumed without plaintext.")
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
	if decodedEnvelope.Kind != "text" && decodedEnvelope.Kind != "file" && decodedEnvelope.Kind != "bundle" {
		fmt.Fprintln(stderr, "The encrypted envelope is invalid.")
		return 1
	}

	if *plainStdout {
		if decodedEnvelope.Kind == "bundle" {
			if status.ExpireAfterReveal {
				fmt.Fprintln(stderr, "Bundles cannot be written to stdout. The one-shot secret was consumed and cannot be recovered. Use --output with a directory.")
			} else {
				fmt.Fprintln(stderr, "Bundles cannot be written to stdout. Use --output with a directory.")
			}
			return 2
		}
		fmt.Fprintln(stderr, "Warning: plaintext will now be written to stdout and may enter an agent transcript or shell history.")
		if _, err := stdout.Write(plain); err != nil {
			fmt.Fprintln(stderr, "Could not write plaintext to stdout.")
			return 1
		}
		return 0
	}

	if decodedEnvelope.Kind == "bundle" {
		destination := *output
		if destination == "" {
			destination = defaultReceiveBundle
		}
		if err := writeBundle(destination, plain, *force); err != nil {
			fmt.Fprintln(stderr, "Could not safely write the local output files.")
			return 1
		}
		fmt.Fprintln(stderr, "Saved decrypted bundle items to a local directory.")
		return 0
	}

	destination := *output
	if destination == "" {
		destination = defaultReceiveFile
	}
	if err := writeSecureFile(destination, plain, *force); err != nil {
		fmt.Fprintln(stderr, "Could not safely write the local output file.")
		return 1
	}
	fmt.Fprintln(stderr, "Saved decrypted value to a local file.")
	return 0
}

func prepareReceiveOutput(output string, force bool) error {
	if output != "" {
		return validateReceiveTarget(output, force)
	}
	if err := validateOutputAncestor(defaultReceiveFile, force); err != nil {
		return err
	}
	return validateBundleDirReady(defaultReceiveBundle)
}

func validateReceiveTarget(output string, force bool) error {
	cleaned := filepath.Clean(output)
	if info, err := os.Lstat(cleaned); err == nil {
		if info.IsDir() {
			return validateBundleDirReady(cleaned)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return validateOutputAncestor(output, force)
}

func validateBundleDirReady(destination string) error {
	if filepath.IsAbs(destination) {
		return errors.New("absolute output paths are refused")
	}
	cleaned := filepath.Clean(destination)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return errors.New("unsafe output path")
	}
	if info, err := os.Lstat(cleaned); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("output is not a directory")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	return requireExistingRegularParent(filepath.Dir(cleaned))
}

func httpClient() *http.Client {
	return &http.Client{
		Timeout: 20 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("redirects are not accepted")
		},
	}
}

func defaultOriginValue() string {
	if value := strings.TrimSpace(os.Getenv("ZK_RELAY_ORIGIN")); value != "" {
		return value
	}
	return defaultOrigin
}

func normalizeOrigin(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("invalid origin")
	}
	if !allowedRelayScheme(parsed) {
		return "", errors.New("invalid origin")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	if parsed.Path != "" {
		return "", errors.New("invalid origin")
	}
	return parsed.Scheme + "://" + parsed.Host, nil
}

func allowedRelayScheme(parsed *url.URL) bool {
	if parsed.Scheme == "https" {
		return true
	}
	host := parsed.Hostname()
	return parsed.Scheme == "http" && (host == "127.0.0.1" || host == "localhost")
}

func parseTTL(value string) (int, error) {
	switch strings.TrimSpace(value) {
	case "1h", "3600":
		return 3600, nil
	case "1d", "86400":
		return 86400, nil
	case "7d", "604800":
		return 604800, nil
	default:
		return 0, errors.New("invalid ttl")
	}
}

func resolveLink(link string, linkStdin bool, positional string, stdin io.Reader) (string, error) {
	count := 0
	if strings.TrimSpace(link) != "" {
		count++
	}
	if linkStdin {
		count++
	}
	if strings.TrimSpace(positional) != "" {
		count++
	}
	if count != 1 {
		return "", errors.New("exactly one link source")
	}
	if linkStdin {
		raw, err := io.ReadAll(io.LimitReader(stdin, 8192))
		if err != nil {
			return "", err
		}
		value := strings.TrimSpace(string(raw))
		if value == "" {
			return "", errors.New("empty link")
		}
		return value, nil
	}
	if strings.TrimSpace(link) != "" {
		return strings.TrimSpace(link), nil
	}
	return strings.TrimSpace(positional), nil
}

func readSecretFile(path string) ([]byte, error) {
	if filepath.IsAbs(path) {
		return nil, errors.New("absolute paths refused")
	}
	cleaned := filepath.Clean(path)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return nil, errors.New("unsafe path")
	}
	info, err := os.Lstat(cleaned)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if info.Size() > int64(maxPayloadBytes)+1 {
		return nil, errors.New("too large")
	}
	file, err := os.Open(cleaned)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, int64(maxPayloadBytes)+1))
}

func randomBytes(length int) ([]byte, error) {
	value := make([]byte, length)
	if _, err := rand.Read(value); err != nil {
		return nil, err
	}
	return value, nil
}

func hashAccessToken(token []byte) string {
	sum := sha256.Sum256(token)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func encryptEnvelope(env envelope, key, nonce []byte) ([]byte, error) {
	if len(key) != 32 || len(nonce) != 12 {
		return nil, errors.New("invalid encryption material")
	}
	plain, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	defer zero(plain)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nonce, plain, []byte(protocolAAD)), nil
}

func parseRelayURL(raw string) (capability, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || !allowedRelayScheme(parsed) {
		return capability{}, errors.New("invalid URL")
	}
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(parts) != 2 || (parts[0] != "a" && parts[0] != "h") || !validIdentifier(parts[1]) {
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
	request.Header.Set("Authorization", "zk-relay "+cap.tokenText)
	request.Header.Set("Accept", "application/vnd.zk-relay.encrypted+json")
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
	limited := &io.LimitedReader{R: reader, N: int64(maxResponseBytes) + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if limited.N == 0 {
		return errors.New("response too large")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
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
	if err != nil {
		zero(plain)
		return nil, envelope{}, errors.New("invalid payload")
	}
	zero(plain)
	if decoded.V != 1 || decoded.Name == "" || decoded.MediaType == "" {
		zero(data)
		return nil, envelope{}, errors.New("invalid envelope")
	}
	switch decoded.Kind {
	case "text", "file":
		if len(data) > maxPayloadBytes {
			zero(data)
			return nil, envelope{}, errors.New("invalid payload")
		}
	case "bundle":
		if decoded.MediaType != bundleMediaType || len(data) > maxContainerBytes {
			zero(data)
			return nil, envelope{}, errors.New("invalid envelope")
		}
		itemBytes, _, err := decodeBundleItems(data)
		if err != nil {
			zero(data)
			return nil, envelope{}, errors.New("invalid envelope")
		}
		for _, value := range itemBytes {
			zero(value)
		}
	default:
		zero(data)
		return nil, envelope{}, errors.New("invalid envelope")
	}
	return data, decoded, nil
}

func decodeBundleItems(payload []byte) ([][]byte, []bundleItem, error) {
	var parsed bundlePayload
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&parsed); err != nil {
		return nil, nil, err
	}
	if len(parsed.Items) < 1 || len(parsed.Items) > 2 {
		return nil, nil, errors.New("invalid bundle")
	}
	total := 0
	decoded := make([][]byte, 0, len(parsed.Items))
	for _, item := range parsed.Items {
		if (item.Kind != "text" && item.Kind != "file") || item.Name == "" || item.MediaType == "" {
			for _, value := range decoded {
				zero(value)
			}
			return nil, nil, errors.New("invalid bundle")
		}
		data, err := base64.RawURLEncoding.DecodeString(item.Data)
		if err != nil {
			for _, value := range decoded {
				zero(value)
			}
			return nil, nil, err
		}
		total += len(data)
		if total > maxPayloadBytes {
			zero(data)
			for _, value := range decoded {
				zero(value)
			}
			return nil, nil, errors.New("invalid payload")
		}
		decoded = append(decoded, data)
	}
	return decoded, parsed.Items, nil
}

func writeBundle(destination string, payload []byte, force bool) error {
	itemBytes, items, err := decodeBundleItems(payload)
	if err != nil {
		return err
	}
	defer func() {
		for _, value := range itemBytes {
			zero(value)
		}
	}()
	if err := prepareOutputDir(destination); err != nil {
		return err
	}
	used := map[string]bool{}
	for index, item := range items {
		name := sanitizeFilename(item.Name)
		if used[name] {
			return errors.New("duplicate output name")
		}
		used[name] = true
		path := filepath.Join(destination, name)
		if err := writeSecureFile(path, itemBytes[index], force); err != nil {
			return err
		}
	}
	return nil
}

func prepareOutputDir(destination string) error {
	if filepath.IsAbs(destination) {
		return errors.New("absolute output paths are refused")
	}
	cleaned := filepath.Clean(destination)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return errors.New("unsafe output path")
	}
	if info, err := os.Lstat(cleaned); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("output is not a directory")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	parent := filepath.Dir(cleaned)
	if err := requireExistingRegularParent(parent); err != nil {
		return err
	}
	return os.Mkdir(cleaned, 0o700)
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
	if err := validateOutputPath(destination, force); err != nil {
		return err
	}
	cleaned := filepath.Clean(destination)
	parent := filepath.Dir(cleaned)

	temporary, err := os.CreateTemp(parent, ".zk-relay-")
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
		// ponytail: Link is preferred (no overwrite race); Rename covers filesystems without hard links.
		return os.Rename(temporaryName, cleaned)
	}
	return os.Remove(temporaryName)
}

func validateOutputAncestor(destination string, force bool) error {
	if filepath.IsAbs(destination) {
		return errors.New("absolute output paths are refused")
	}
	cleaned := filepath.Clean(destination)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return errors.New("unsafe output path")
	}
	if info, err := os.Lstat(cleaned); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("unsafe output path")
		}
		if info.Mode().IsRegular() && !force {
			return errors.New("output exists")
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return errors.New("unsafe output path")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return requireExistingRegularParent(filepath.Dir(cleaned))
}

func validateOutputPath(destination string, force bool) error {
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
	return nil
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
