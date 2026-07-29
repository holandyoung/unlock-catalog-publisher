package signing

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

func TestEncryptedFileProviderSignsAndClearsOnClose(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "test-key.age")
	passphrase := []byte("deterministic test passphrase")
	writeEncryptedTestKey(t, keyPath, "test-a", 0x41, passphrase, nil)

	provider, err := OpenEncryptedFileProvider(keyPath, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if provider.KeyID() != "test-a" {
		t.Fatalf("key ID = %q", provider.KeyID())
	}
	publicKey, err := provider.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("canonical test payload")
	signature, err := provider.Sign(message)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(publicKey, message, signature) {
		t.Fatal("provider signature did not verify")
	}
	concrete := provider.(*encryptedFileProvider)
	privateBacking := concrete.private
	publicBacking := concrete.public
	if err := provider.Close(); err != nil {
		t.Fatal(err)
	}
	if !allZero(privateBacking) || !allZero(publicBacking) {
		t.Fatal("provider close did not clear controlled key buffers")
	}
	if _, err := provider.Sign(message); err == nil {
		t.Fatal("closed provider retained usable key material")
	}
}

func allZero(content []byte) bool {
	for _, value := range content {
		if value != 0 {
			return false
		}
	}
	return true
}

func TestEncryptedFileProviderRejectsUnsafeInputs(t *testing.T) {
	passphrase := []byte("deterministic test passphrase")
	tests := map[string]func(*testing.T) (string, []byte){
		"wrong passphrase": func(t *testing.T) (string, []byte) {
			path := filepath.Join(t.TempDir(), "key.age")
			writeEncryptedTestKey(t, path, "test-a", 0x41, passphrase, nil)
			return path, []byte("wrong test passphrase")
		},
		"world readable": func(t *testing.T) (string, []byte) {
			path := filepath.Join(t.TempDir(), "key.age")
			writeEncryptedTestKey(t, path, "test-a", 0x41, passphrase, nil)
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
			return path, passphrase
		},
		"symlink": func(t *testing.T) (string, []byte) {
			directory := t.TempDir()
			target := filepath.Join(directory, "target.age")
			writeEncryptedTestKey(t, target, "test-a", 0x41, passphrase, nil)
			link := filepath.Join(directory, "link.age")
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			return link, passphrase
		},
		"tampered ciphertext": func(t *testing.T) (string, []byte) {
			path := filepath.Join(t.TempDir(), "key.age")
			writeEncryptedTestKey(t, path, "test-a", 0x41, passphrase, nil)
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			content[len(content)-1] ^= 0xff
			if err := os.WriteFile(path, content, 0o600); err != nil {
				t.Fatal(err)
			}
			return path, passphrase
		},
		"unknown plaintext field": func(t *testing.T) (string, []byte) {
			path := filepath.Join(t.TempDir(), "key.age")
			writeEncryptedTestKey(t, path, "test-a", 0x41, passphrase, map[string]any{"command": "run"})
			return path, passphrase
		},
		"invalid key id": func(t *testing.T) (string, []byte) {
			path := filepath.Join(t.TempDir(), "key.age")
			writeEncryptedTestKey(t, path, "../test-a", 0x41, passphrase, nil)
			return path, passphrase
		},
	}

	for name, setup := range tests {
		t.Run(name, func(t *testing.T) {
			path, password := setup(t)
			if provider, err := OpenEncryptedFileProvider(path, password); err == nil {
				provider.Close()
				t.Fatal("unsafe encrypted key input was accepted")
			}
		})
	}
}

func TestReadPassphraseFileRequiresOwnerOnlyRegularFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "passphrase")
	want := []byte("deterministic test passphrase")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadPassphraseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("passphrase bytes changed")
	}
	clearBytes(got)
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPassphraseFile(path); err == nil {
		t.Fatal("group-readable passphrase file was accepted")
	}
	link := filepath.Join(directory, "passphrase-link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPassphraseFile(link); err == nil {
		t.Fatal("symlink passphrase file was accepted")
	}
}

func writeEncryptedTestKey(t *testing.T, path, keyID string, marker byte, passphrase []byte, extra map[string]any) {
	t.Helper()
	plaintext := map[string]any{
		"schemaVersion": 1,
		"algorithm":     "Ed25519",
		"keyId":         keyID,
		"seed":          base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{marker}, ed25519.SeedSize)),
	}
	for key, value := range extra {
		plaintext[key] = value
	}
	content, err := json.Marshal(plaintext)
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
	if _, err := writer.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	clearBytes(content)
}
