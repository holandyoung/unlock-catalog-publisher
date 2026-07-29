package signing

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
)

var keyIDPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

type KeyProvider interface {
	KeyID() string
	PublicKey() (ed25519.PublicKey, error)
	Sign(message []byte) ([]byte, error)
	Close() error
}

type Fragment struct {
	RequestDigest string `json:"requestDigest"`
	KeyID         string `json:"keyId"`
	Signature     string `json:"signature"`
}

func Inspect(candidateRoot string) (Inspection, error) {
	candidate, err := Prepare(candidateRoot)
	if err != nil {
		return Inspection{}, err
	}
	return candidate.Inspection(), nil
}

func Sign(candidateRoot string, provider KeyProvider) (Fragment, error) {
	candidate, err := Prepare(candidateRoot)
	if err != nil {
		return Fragment{}, err
	}
	return candidate.Sign(provider)
}

func Prepare(candidateRoot string) (*PreparedCandidate, error) {
	return inspectCandidate(candidateRoot)
}

func (candidate *PreparedCandidate) Sign(provider KeyProvider) (Fragment, error) {
	if candidate == nil {
		return Fragment{}, fmt.Errorf("prepared candidate is required")
	}
	if provider == nil {
		return Fragment{}, fmt.Errorf("key provider is required")
	}
	keyID := provider.KeyID()
	if !keyIDPattern.MatchString(keyID) {
		return Fragment{}, fmt.Errorf("provider key ID is invalid")
	}
	publicKey, err := provider.PublicKey()
	if err != nil {
		return Fragment{}, fmt.Errorf("read provider public key: %w", err)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return Fragment{}, fmt.Errorf("provider public key has invalid length")
	}
	signature, err := provider.Sign(candidate.payload)
	if err != nil {
		return Fragment{}, fmt.Errorf("sign canonical payload: %w", err)
	}
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, candidate.payload, signature) {
		return Fragment{}, fmt.Errorf("provider returned an invalid signature")
	}
	return Fragment{
		RequestDigest: candidate.inspection.RequestDigest,
		KeyID:         keyID,
		Signature:     base64.StdEncoding.EncodeToString(signature),
	}, nil
}

func EncodeFragment(fragment Fragment) ([]byte, error) {
	if err := validateFragmentShape(fragment); err != nil {
		return nil, err
	}
	return json.Marshal(fragment)
}

// ValidateFragmentSet is the pre-assembly guard. Threshold and root policy are
// deliberately left to the later assembler, but mixed requests and duplicated
// key material are rejected here so fragments cannot be treated as independent.
func ValidateFragmentSet(payload []byte, requestDigest string, fragments []Fragment, publicKeys map[string]ed25519.PublicKey) error {
	if !digestPattern.MatchString(requestDigest) {
		return fmt.Errorf("expected request digest is invalid")
	}
	if len(fragments) == 0 {
		return fmt.Errorf("at least one fragment is required")
	}
	seenIDs := make(map[string]struct{}, len(fragments))
	seenMaterial := make([]ed25519.PublicKey, 0, len(fragments))
	for _, fragment := range fragments {
		if err := validateFragmentShape(fragment); err != nil {
			return err
		}
		if fragment.RequestDigest != requestDigest {
			return fmt.Errorf("fragment request digest mismatch")
		}
		if _, duplicate := seenIDs[fragment.KeyID]; duplicate {
			return fmt.Errorf("duplicate fragment key ID %q", fragment.KeyID)
		}
		seenIDs[fragment.KeyID] = struct{}{}
		publicKey, ok := publicKeys[fragment.KeyID]
		if !ok || len(publicKey) != ed25519.PublicKeySize {
			return fmt.Errorf("fragment key %q is not trusted", fragment.KeyID)
		}
		for _, prior := range seenMaterial {
			if bytes.Equal(prior, publicKey) {
				return fmt.Errorf("fragment key IDs reuse the same key material")
			}
		}
		seenMaterial = append(seenMaterial, append(ed25519.PublicKey(nil), publicKey...))
		signature, err := base64.StdEncoding.Strict().DecodeString(fragment.Signature)
		if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, payload, signature) {
			return fmt.Errorf("fragment signature for %q is invalid", fragment.KeyID)
		}
	}
	return nil
}

func validateFragmentShape(fragment Fragment) error {
	if !digestPattern.MatchString(fragment.RequestDigest) {
		return fmt.Errorf("fragment request digest is invalid")
	}
	if !keyIDPattern.MatchString(fragment.KeyID) {
		return fmt.Errorf("fragment key ID is invalid")
	}
	if fragment.Signature == "" {
		return fmt.Errorf("fragment signature is required")
	}
	return nil
}
