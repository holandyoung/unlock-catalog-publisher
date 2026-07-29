package signing

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"io"
	"path/filepath"
	"sync"

	"filippo.io/age"
)

const (
	maxEncryptedKeyBytes = 1 << 20
	maxKeyPlaintextBytes = 4 << 10
	maxPassphraseBytes   = 4 << 10
)

type encryptedKeyEnvelope struct {
	SchemaVersion int    `json:"schemaVersion"`
	Algorithm     string `json:"algorithm"`
	KeyID         string `json:"keyId"`
	Seed          []byte `json:"seed"`
}

type encryptedFileProvider struct {
	mu      sync.Mutex
	keyID   string
	public  ed25519.PublicKey
	private ed25519.PrivateKey
	closed  bool
}

func OpenEncryptedFileProvider(filePath string, passphrase []byte) (KeyProvider, error) {
	if len(passphrase) == 0 || len(passphrase) > maxPassphraseBytes {
		return nil, fmt.Errorf("passphrase length is invalid")
	}
	encrypted, err := readOwnerOnlyFile(filePath, maxEncryptedKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("read encrypted key: %w", err)
	}
	defer clearBytes(encrypted)
	identity, err := age.NewScryptIdentity(string(passphrase))
	if err != nil {
		return nil, fmt.Errorf("initialize encrypted key identity: %w", err)
	}
	reader, err := age.Decrypt(bytes.NewReader(encrypted), identity)
	if err != nil {
		return nil, fmt.Errorf("decrypt encrypted key: %w", err)
	}
	plaintext, err := io.ReadAll(io.LimitReader(reader, maxKeyPlaintextBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read decrypted key: %w", err)
	}
	defer clearBytes(plaintext)
	if len(plaintext) > maxKeyPlaintextBytes {
		return nil, fmt.Errorf("decrypted key exceeds %d bytes", maxKeyPlaintextBytes)
	}
	var envelope encryptedKeyEnvelope
	if err := decodeStrictJSON(plaintext, &envelope); err != nil {
		return nil, fmt.Errorf("decode decrypted key: %w", err)
	}
	defer clearBytes(envelope.Seed)
	if envelope.SchemaVersion != 1 || envelope.Algorithm != "Ed25519" {
		return nil, fmt.Errorf("encrypted key schema or algorithm is invalid")
	}
	if !keyIDPattern.MatchString(envelope.KeyID) {
		return nil, fmt.Errorf("encrypted key ID is invalid")
	}
	if len(envelope.Seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("encrypted Ed25519 seed has invalid length")
	}
	privateKey := ed25519.NewKeyFromSeed(envelope.Seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return &encryptedFileProvider{
		keyID:   envelope.KeyID,
		public:  publicKey,
		private: privateKey,
	}, nil
}

func ReadPassphraseFile(filePath string) ([]byte, error) {
	content, err := readOwnerOnlyFile(filePath, maxPassphraseBytes)
	if err != nil {
		return nil, err
	}
	if len(content) == 0 {
		return nil, fmt.Errorf("passphrase file is empty")
	}
	return content, nil
}

func (provider *encryptedFileProvider) KeyID() string {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return provider.keyID
}

func (provider *encryptedFileProvider) PublicKey() (ed25519.PublicKey, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if provider.closed {
		return nil, fmt.Errorf("key provider is closed")
	}
	return append(ed25519.PublicKey(nil), provider.public...), nil
}

func (provider *encryptedFileProvider) Sign(message []byte) ([]byte, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if provider.closed {
		return nil, fmt.Errorf("key provider is closed")
	}
	return ed25519.Sign(provider.private, message), nil
}

func (provider *encryptedFileProvider) Close() error {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if provider.closed {
		return nil
	}
	clearBytes(provider.private)
	clearBytes(provider.public)
	provider.private = nil
	provider.public = nil
	provider.closed = true
	return nil
}

func readOwnerOnlyFile(filePath string, maximum int64) ([]byte, error) {
	absolute, err := filepathAbs(filePath)
	if err != nil {
		return nil, err
	}
	file, err := openNoSymlinks(absolute)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Mode().Perm()&0o111 != 0 {
		return nil, fmt.Errorf("sensitive input must be an owner-only non-executable regular file")
	}
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > maximum {
		clearBytes(content)
		return nil, fmt.Errorf("sensitive input exceeds %d bytes", maximum)
	}
	return content, nil
}

func filepathAbs(filePath string) (string, error) {
	if filePath == "" {
		return "", fmt.Errorf("file path is required")
	}
	return filepath.Abs(filePath)
}

func clearBytes(content []byte) {
	for index := range content {
		content[index] = 0
	}
}
