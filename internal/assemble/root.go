package assemble

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"time"

	"github.com/holandyoung/unlock-catalog/internal/catalogv1"
	"github.com/holandyoung/unlock-catalog/internal/signing"
)

const bridgeCompatibilityWindow = 90 * 24 * time.Hour

var rootKeyIDPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

type TrustRoot struct {
	Version   uint64            `json:"version"`
	Threshold int               `json:"threshold"`
	ExpiresAt time.Time         `json:"expiresAt"`
	Keys      map[string]string `json:"keys"`
}

type Signature struct {
	KeyID string `json:"keyId"`
	Value string `json:"value"`
}

type SignedRoot struct {
	Signed     TrustRoot   `json:"signed"`
	Signatures []Signature `json:"signatures"`
}

func VerifyThreshold(payload []byte, requestDigest string, fragments []signing.Fragment, root TrustRoot) error {
	keys, err := validateRoot(root)
	if err != nil {
		return err
	}
	if !validDigest(requestDigest) {
		return fmt.Errorf("request digest is invalid")
	}
	if len(fragments) < root.Threshold {
		return fmt.Errorf("signature threshold not met")
	}
	seen := make(map[string]struct{}, len(fragments))
	valid := 0
	for _, fragment := range fragments {
		if fragment.RequestDigest != requestDigest {
			return fmt.Errorf("fragment request digest mismatch")
		}
		if _, duplicate := seen[fragment.KeyID]; duplicate {
			return fmt.Errorf("duplicate fragment key ID %q", fragment.KeyID)
		}
		seen[fragment.KeyID] = struct{}{}
		publicKey, trusted := keys[fragment.KeyID]
		if !trusted {
			return fmt.Errorf("fragment key %q is not trusted", fragment.KeyID)
		}
		signature, err := base64.StdEncoding.Strict().DecodeString(fragment.Signature)
		if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, payload, signature) {
			return fmt.Errorf("fragment signature for %q is invalid", fragment.KeyID)
		}
		valid++
	}
	if valid < root.Threshold {
		return fmt.Errorf("signature threshold not met")
	}
	return nil
}

func AssembleSignedRoot(current, next TrustRoot, fragments []signing.Fragment, now time.Time) (SignedRoot, error) {
	currentKeys, err := validateRoot(current)
	if err != nil {
		return SignedRoot{}, fmt.Errorf("current root: %w", err)
	}
	nextKeys, err := validateRoot(next)
	if err != nil {
		return SignedRoot{}, fmt.Errorf("next root: %w", err)
	}
	if now.IsZero() || !now.Equal(now.UTC()) {
		return SignedRoot{}, fmt.Errorf("current UTC time is required")
	}
	if next.Version <= current.Version {
		return SignedRoot{}, fmt.Errorf("root version must increase")
	}
	compatibilityDeadline := now.Add(bridgeCompatibilityWindow)
	if current.ExpiresAt.Before(compatibilityDeadline) || next.ExpiresAt.Before(compatibilityDeadline) {
		return SignedRoot{}, fmt.Errorf("root compatibility window must be at least 90 days")
	}
	shared := 0
	for keyID, currentKey := range currentKeys {
		if nextKey, ok := nextKeys[keyID]; ok && bytes.Equal(currentKey, nextKey) {
			shared++
		}
	}
	if shared < current.Threshold || shared < next.Threshold {
		return SignedRoot{}, fmt.Errorf("root bridge must retain threshold-compatible key material")
	}
	payload, err := json.Marshal(next)
	if err != nil {
		return SignedRoot{}, fmt.Errorf("canonical next root: %w", err)
	}
	digest := catalogv1.DigestBytes(payload)
	if err := verifyBridgeFragments(payload, digest, fragments, current, next); err != nil {
		return SignedRoot{}, err
	}
	signatures := make([]Signature, 0, len(fragments))
	for _, fragment := range fragments {
		signatures = append(signatures, Signature{KeyID: fragment.KeyID, Value: fragment.Signature})
	}
	sort.Slice(signatures, func(i, j int) bool { return signatures[i].KeyID < signatures[j].KeyID })
	return SignedRoot{Signed: next, Signatures: signatures}, nil
}

func verifyBridgeFragments(payload []byte, digest string, fragments []signing.Fragment, current, next TrustRoot) error {
	union := make(map[string]string, len(current.Keys)+len(next.Keys))
	for keyID, material := range current.Keys {
		union[keyID] = material
	}
	for keyID, material := range next.Keys {
		if prior, exists := union[keyID]; exists && prior != material {
			return fmt.Errorf("root key ID %q changes public key material", keyID)
		}
		union[keyID] = material
	}
	seen := make(map[string]struct{}, len(fragments))
	oldFragments := make([]signing.Fragment, 0, len(fragments))
	newFragments := make([]signing.Fragment, 0, len(fragments))
	for _, fragment := range fragments {
		if fragment.RequestDigest != digest {
			return fmt.Errorf("root fragment request digest mismatch")
		}
		if _, duplicate := seen[fragment.KeyID]; duplicate {
			return fmt.Errorf("duplicate root fragment key ID %q", fragment.KeyID)
		}
		seen[fragment.KeyID] = struct{}{}
		encoded, ok := union[fragment.KeyID]
		if !ok {
			return fmt.Errorf("root fragment key %q is not trusted", fragment.KeyID)
		}
		publicKey, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || len(publicKey) != ed25519.PublicKeySize {
			return fmt.Errorf("root fragment key %q is invalid", fragment.KeyID)
		}
		signature, err := base64.StdEncoding.Strict().DecodeString(fragment.Signature)
		if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(publicKey), payload, signature) {
			return fmt.Errorf("root fragment signature for %q is invalid", fragment.KeyID)
		}
		if _, ok := current.Keys[fragment.KeyID]; ok {
			oldFragments = append(oldFragments, fragment)
		}
		if _, ok := next.Keys[fragment.KeyID]; ok {
			newFragments = append(newFragments, fragment)
		}
	}
	if err := VerifyThreshold(payload, digest, oldFragments, current); err != nil {
		return fmt.Errorf("current root threshold: %w", err)
	}
	if err := VerifyThreshold(payload, digest, newFragments, next); err != nil {
		return fmt.Errorf("next root threshold: %w", err)
	}
	return nil
}

func verifySignedRoot(current TrustRoot, signed SignedRoot, now time.Time) error {
	payload, err := json.Marshal(signed.Signed)
	if err != nil {
		return err
	}
	digest := catalogv1.DigestBytes(payload)
	fragments := make([]signing.Fragment, 0, len(signed.Signatures))
	for _, signature := range signed.Signatures {
		fragments = append(fragments, signing.Fragment{RequestDigest: digest, KeyID: signature.KeyID, Signature: signature.Value})
	}
	assembled, err := AssembleSignedRoot(current, signed.Signed, fragments, now)
	if err != nil {
		return err
	}
	if !reflectSignaturesEqual(assembled.Signatures, signed.Signatures) {
		return fmt.Errorf("signed root signatures are not canonical")
	}
	return nil
}

func validateRoot(root TrustRoot) (map[string]ed25519.PublicKey, error) {
	if root.Version == 0 || root.Threshold != 2 || len(root.Keys) != 3 || root.ExpiresAt.IsZero() {
		return nil, fmt.Errorf("root must be versioned 2-of-3 metadata with an expiry")
	}
	keys := make(map[string]ed25519.PublicKey, len(root.Keys))
	seenMaterial := make(map[string]struct{}, len(root.Keys))
	for keyID, encoded := range root.Keys {
		if !rootKeyIDPattern.MatchString(keyID) {
			return nil, fmt.Errorf("root key ID %q is invalid", keyID)
		}
		material, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || len(material) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("root key %q is not Ed25519", keyID)
		}
		if _, duplicate := seenMaterial[string(material)]; duplicate {
			return nil, fmt.Errorf("root reuses Ed25519 public key material")
		}
		seenMaterial[string(material)] = struct{}{}
		keys[keyID] = ed25519.PublicKey(append([]byte(nil), material...))
	}
	return keys, nil
}

func validDigest(value string) bool {
	if len(value) != sha256HexLength {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

const sha256HexLength = 64

func reflectSignaturesEqual(left, right []Signature) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
