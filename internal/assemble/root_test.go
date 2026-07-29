package assemble

import (
	"testing"
	"time"

	"github.com/holandyoung/unlock-catalog/internal/signing"
)

func TestAssembleSignedRootRequiresBridgeThresholdsAndCompatibilityWindow(t *testing.T) {
	now := time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC)
	keys := testKeys(t, "a", "b", "c", "d", "e", "f")
	current := testRoot(1, now.Add(180*24*time.Hour), keys, "a", "b", "c")
	next := testRoot(2, now.Add(180*24*time.Hour), keys, "a", "b", "d")
	digest, payload := rootSigningPayload(t, next)
	valid := []signing.Fragment{
		testFragment(payload, digest, keys["a"]),
		testFragment(payload, digest, keys["b"]),
	}
	if _, err := AssembleSignedRoot(current, next, valid, now); err != nil {
		t.Fatalf("valid bridge: %v", err)
	}
	shortCurrent := testRoot(1, now.Add(90*24*time.Hour-time.Second), keys, "a", "b", "c")
	if _, err := AssembleSignedRoot(shortCurrent, next, valid, now); err == nil {
		t.Fatal("AssembleSignedRoot accepted an old root with less than 90 days remaining")
	}

	tests := map[string]func() (TrustRoot, []signing.Fragment){
		"old threshold missing": func() (TrustRoot, []signing.Fragment) {
			fragments := []signing.Fragment{
				testFragment(payload, digest, keys["a"]),
				testFragment(payload, digest, keys["d"]),
			}
			return next, fragments
		},
		"new threshold missing": func() (TrustRoot, []signing.Fragment) {
			fragments := []signing.Fragment{
				testFragment(payload, digest, keys["a"]),
				testFragment(payload, digest, keys["c"]),
			}
			return next, fragments
		},
		"all keys replaced": func() (TrustRoot, []signing.Fragment) {
			replacement := testRoot(2, now.Add(180*24*time.Hour), keys, "d", "e", "f")
			replacementDigest, replacementPayload := rootSigningPayload(t, replacement)
			return replacement, []signing.Fragment{
				testFragment(replacementPayload, replacementDigest, keys["a"]),
				testFragment(replacementPayload, replacementDigest, keys["b"]),
				testFragment(replacementPayload, replacementDigest, keys["d"]),
				testFragment(replacementPayload, replacementDigest, keys["e"]),
			}
		},
		"window shorter than 90 days": func() (TrustRoot, []signing.Fragment) {
			short := testRoot(2, now.Add(90*24*time.Hour-time.Second), keys, "a", "b", "d")
			shortDigest, shortPayload := rootSigningPayload(t, short)
			return short, []signing.Fragment{
				testFragment(shortPayload, shortDigest, keys["a"]),
				testFragment(shortPayload, shortDigest, keys["b"]),
			}
		},
	}
	for name, build := range tests {
		t.Run(name, func(t *testing.T) {
			candidate, fragments := build()
			if _, err := AssembleSignedRoot(current, candidate, fragments, now); err == nil {
				t.Fatal("AssembleSignedRoot accepted unsafe bridge")
			}
		})
	}
}
