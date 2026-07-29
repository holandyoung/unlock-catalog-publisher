package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/holandyoung/unlock-catalog-publisher/internal/signing"
)

func TestInspectCommandReportsOnlySafeMetadata(t *testing.T) {
	candidate := filepath.Join("..", "..", "fixtures", "v1", "candidate", "valid", "unlock-official-linux-amd64-static")
	var stdout, stderr bytes.Buffer
	if err := run([]string{"inspect", "--candidate", candidate}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	var report map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("inspect output is not JSON: %v", err)
	}
	for _, key := range []string{"sourceId", "version", "requestDigest", "payloadSha256", "objectCount"} {
		if _, ok := report[key]; !ok {
			t.Fatalf("inspect output lacks %s: %v", key, report)
		}
	}
	for _, forbidden := range []string{"signature", "key", "seed", "passphrase"} {
		if bytes.Contains(bytes.ToLower(stdout.Bytes()), []byte(forbidden)) {
			t.Fatalf("inspect output contains sensitive or signing field %q", forbidden)
		}
	}
}

func TestCommandBoundaryRejectsNonAllowlistedActions(t *testing.T) {
	for name, args := range map[string][]string{
		"missing":                      nil,
		"publisher command":            {"candidate"},
		"shell":                        {"sh", "-c", "true"},
		"assemble":                     {"assemble"},
		"sign without required inputs": {"sign"},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := run(args, &stdout, &stderr); err == nil {
				t.Fatal("non-allowlisted or incomplete command was accepted")
			}
			if stdout.Len() != 0 {
				t.Fatalf("failed command wrote stdout: %q", stdout.String())
			}
		})
	}
}

func TestSignCommandWritesExactFragmentWithoutLeakingInputs(t *testing.T) {
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "test-key.age")
	passphrasePath := filepath.Join(directory, "passphrase")
	outputPath := filepath.Join(directory, "fragment.json")
	passphrase := []byte("deterministic command test passphrase")
	writeCommandTestKey(t, keyPath, passphrase)
	if err := os.WriteFile(passphrasePath, passphrase, 0o600); err != nil {
		t.Fatal(err)
	}
	candidate := filepath.Join("..", "..", "fixtures", "v1", "candidate", "valid", "unlock-official-linux-amd64-static")
	inspection, err := signing.Inspect(candidate)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	args := []string{"sign", "--candidate", candidate, "--expect-request-digest", inspection.RequestDigest, "--encrypted-key", keyPath, "--passphrase-file", passphrasePath, "--output", outputPath}
	if err := run(args, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if stdout.Len() != 0 || bytes.Contains(stderr.Bytes(), passphrase) {
		t.Fatal("sign command leaked input data")
	}
	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	var fragment map[string]json.RawMessage
	if err := json.Unmarshal(content, &fragment); err != nil {
		t.Fatal(err)
	}
	if len(fragment) != 3 || fragment["requestDigest"] == nil || fragment["keyId"] == nil || fragment["signature"] == nil {
		t.Fatalf("fragment shape = %s", content)
	}
	original := append([]byte(nil), content...)
	if err := run(args, &stdout, &stderr); err == nil {
		t.Fatal("sign command overwrote an existing fragment")
	}
	content, err = os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, original) {
		t.Fatal("failed second sign changed existing fragment")
	}
}

func TestSignCommandRejectsCandidateBeforeOpeningProvider(t *testing.T) {
	candidate := filepath.Join(t.TempDir(), "candidate")
	if err := os.Mkdir(candidate, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(candidate, "unexpected"), []byte("not a candidate"), 0o644); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	output := filepath.Join(t.TempDir(), "fragment.json")
	var stdout, stderr bytes.Buffer
	err := run([]string{
		"sign", "--candidate", candidate,
		"--expect-request-digest", strings.Repeat("a", 64),
		"--encrypted-key", missing,
		"--passphrase-file", missing,
		"--output", output,
	}, &stdout, &stderr)
	if err == nil {
		t.Fatal("invalid candidate was accepted")
	}
	if !strings.Contains(err.Error(), "manifest payload") {
		t.Fatalf("provider was touched before candidate preflight: %v", err)
	}
}

func TestSignCommandRejectsOutputInsideCandidateBeforeOpeningProvider(t *testing.T) {
	candidate := filepath.Join("..", "..", "fixtures", "v1", "candidate", "valid", "unlock-official-linux-amd64-static")
	output := filepath.Join(candidate, "fragment.json")
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	var stdout, stderr bytes.Buffer
	err := run([]string{
		"sign", "--candidate", candidate,
		"--expect-request-digest", strings.Repeat("a", 64),
		"--encrypted-key", missing,
		"--passphrase-file", missing,
		"--output", output,
	}, &stdout, &stderr)
	if err == nil {
		t.Fatal("output inside candidate was accepted")
	}
	if !strings.Contains(err.Error(), "outside candidate") {
		t.Fatalf("provider was touched before output validation: %v", err)
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("invalid output changed candidate: %v", err)
	}
}

func TestSignCommandRejectsUnexpectedRequestDigestBeforeOpeningProvider(t *testing.T) {
	candidate := filepath.Join("..", "..", "fixtures", "v1", "candidate", "valid", "unlock-official-linux-amd64-static")
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	output := filepath.Join(t.TempDir(), "fragment.json")
	var stdout, stderr bytes.Buffer
	err := run([]string{
		"sign", "--candidate", candidate,
		"--expect-request-digest", strings.Repeat("b", 64),
		"--encrypted-key", missing,
		"--passphrase-file", missing,
		"--output", output,
	}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "request digest") {
		t.Fatalf("unexpected digest did not fail before provider: %v", err)
	}
}

func writeCommandTestKey(t *testing.T, path string, passphrase []byte) {
	t.Helper()
	plaintext, err := json.Marshal(map[string]any{
		"schemaVersion": 1,
		"algorithm":     "Ed25519",
		"keyId":         "test-command",
		"seed":          base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x51}, ed25519.SeedSize)),
	})
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := age.NewScryptRecipient(string(passphrase))
	if err != nil {
		t.Fatal(err)
	}
	recipient.SetWorkFactor(10)
	writer, err := age.Encrypt(file, recipient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
