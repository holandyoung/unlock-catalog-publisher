package signing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/holandyoung/unlock-catalog/internal/catalogv1"
)

type memoryProvider struct {
	id      string
	private ed25519.PrivateKey
	calls   int
}

func newMemoryProvider(id string, marker byte) *memoryProvider {
	seed := bytes.Repeat([]byte{marker}, ed25519.SeedSize)
	return &memoryProvider{id: id, private: ed25519.NewKeyFromSeed(seed)}
}

func (provider *memoryProvider) KeyID() string { return provider.id }

func (provider *memoryProvider) PublicKey() (ed25519.PublicKey, error) {
	public := provider.private.Public().(ed25519.PublicKey)
	return append(ed25519.PublicKey(nil), public...), nil
}

func (provider *memoryProvider) Sign(message []byte) ([]byte, error) {
	provider.calls++
	return ed25519.Sign(provider.private, message), nil
}

func (provider *memoryProvider) Close() error { return nil }

func TestInspectAndSignCanonicalCandidateWithoutMutation(t *testing.T) {
	candidate := copyCandidate(t)
	before := snapshotTree(t, candidate)

	inspection, err := Inspect(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if inspection.SourceID != "unlock-official-linux-amd64-static" || inspection.Version != 1 || inspection.ObjectCount != 3 {
		t.Fatalf("unexpected inspection: %+v", inspection)
	}
	if len(inspection.RequestDigest) != sha256.Size*2 || inspection.PayloadSHA256 != "45c1c318e72ac9e18b10e79a566f36b91c8bfca2b19119f0ef4f3793eb3f663d" {
		t.Fatalf("unexpected digests: %+v", inspection)
	}

	provider := newMemoryProvider("test-a", 0x11)
	fragment, err := Sign(candidate, provider)
	if err != nil {
		t.Fatal(err)
	}
	if provider.calls != 1 || fragment.KeyID != "test-a" || fragment.RequestDigest != inspection.RequestDigest {
		t.Fatalf("unexpected fragment/provider state: %+v calls=%d", fragment, provider.calls)
	}
	payload, err := os.ReadFile(filepath.Join(candidate, "manifest.payload.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateFragmentSet(payload, inspection.RequestDigest, []Fragment{fragment}, map[string]ed25519.PublicKey{"test-a": provider.private.Public().(ed25519.PublicKey)}); err != nil {
		t.Fatalf("validate fragment: %v", err)
	}
	if after := snapshotTree(t, candidate); !equalSnapshots(before, after) {
		t.Fatal("inspect/sign mutated the candidate")
	}
}

func TestInspectRejectsCandidateBoundaryViolations(t *testing.T) {
	tests := map[string]func(*testing.T, string){
		"policy mismatch": func(t *testing.T, root string) {
			mutateRequest(t, root, func(request *catalogv1.SigningRequest) { request.PolicyVersion = "other-policy" })
		},
		"source mismatch": func(t *testing.T, root string) {
			mutateRequest(t, root, func(request *catalogv1.SigningRequest) { request.SourceID = "other-source" })
		},
		"version mismatch": func(t *testing.T, root string) {
			mutateRequest(t, root, func(request *catalogv1.SigningRequest) { request.Version++ })
		},
		"object digest mismatch": func(t *testing.T, root string) {
			request := readRequest(t, root)
			if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(request.Objects[0].Path)), []byte("changed"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"unknown file": func(t *testing.T, root string) {
			if err := os.WriteFile(filepath.Join(root, "run.sh"), []byte("exit 0\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"symlink": func(t *testing.T, root string) {
			object := firstObjectPath(t, root)
			if err := os.Remove(object); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(root, "manifest.payload.json"), object); err != nil {
				t.Fatal(err)
			}
		},
		"special file": func(t *testing.T, root string) {
			object := firstObjectPath(t, root)
			if err := os.Remove(object); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(object, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"candidate executable": func(t *testing.T, root string) {
			if err := os.Chmod(firstObjectPath(t, root), 0o755); err != nil {
				t.Fatal(err)
			}
		},
		"noncanonical file mode": func(t *testing.T, root string) {
			if err := os.Chmod(firstObjectPath(t, root), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"noncanonical directory mode": func(t *testing.T, root string) {
			if err := os.Chmod(filepath.Dir(firstObjectPath(t, root)), 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"unknown request field": func(t *testing.T, root string) {
			path := filepath.Join(root, "signing-request.json")
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			content = append(content[:len(content)-1], []byte(`,"command":"run"}`)...)
			if err := os.WriteFile(path, content, 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"duplicate request field": func(t *testing.T, root string) {
			path := filepath.Join(root, "signing-request.json")
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			content = append(content[:len(content)-1], []byte(`,"version":1}`)...)
			if err := os.WriteFile(path, content, 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"unknown payload field": func(t *testing.T, root string) {
			path := filepath.Join(root, "manifest.payload.json")
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			content = append(content[:len(content)-1], []byte(`,"command":"run"}`)...)
			if err := os.WriteFile(path, content, 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"non UTC build time": func(t *testing.T, root string) {
			payloadPath := filepath.Join(root, "manifest.payload.json")
			var manifest catalogv1.Manifest
			decodeJSONFile(t, payloadPath, &manifest)
			offset := time.FixedZone("test-offset", 60*60)
			manifest.PublishedAt = manifest.PublishedAt.In(offset)
			manifest.ExpiresAt = manifest.ExpiresAt.In(offset)
			payload, err := catalogv1.CanonicalManifest(manifest)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(payloadPath, payload, 0o644); err != nil {
				t.Fatal(err)
			}
			mutateRequest(t, root, func(request *catalogv1.SigningRequest) {
				request.PublishedAt = manifest.PublishedAt
				request.ExpiresAt = manifest.ExpiresAt
				request.PayloadSHA256 = catalogv1.DigestBytes(payload)
			})
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := copyCandidate(t)
			mutate(t, candidate)
			provider := newMemoryProvider("test-a", 0x11)
			if _, err := Sign(candidate, provider); err == nil {
				t.Fatal("unsafe candidate was accepted")
			}
			if provider.calls != 0 {
				t.Fatal("provider signed before candidate validation completed")
			}
		})
	}
}

func TestInspectRejectsPayloadDigestDriftAtDigestCheck(t *testing.T) {
	candidate := copyCandidate(t)
	payloadPath := filepath.Join(candidate, "manifest.payload.json")
	var manifest catalogv1.Manifest
	decodeJSONFile(t, payloadPath, &manifest)
	manifest.Entries[0].Description = "canonical payload changed after request creation"
	payload, err := catalogv1.CanonicalManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(payloadPath, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	provider := newMemoryProvider("test-a", 0x71)
	if _, err := Sign(candidate, provider); err == nil || !strings.Contains(err.Error(), "payload digest mismatch") {
		t.Fatalf("payload digest drift reached wrong check: %v", err)
	}
	if provider.calls != 0 {
		t.Fatal("provider signed payload digest drift")
	}
}

func TestInspectRejectsCoherentNoncanonicalObjectPathAtPolicyCheck(t *testing.T) {
	candidate := copyCandidate(t)
	payloadPath := filepath.Join(candidate, "manifest.payload.json")
	var manifest catalogv1.Manifest
	decodeJSONFile(t, payloadPath, &manifest)
	manifest.Artifacts[0].Path = "objects/not-content-addressed"
	payload, err := catalogv1.CanonicalManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(payloadPath, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	request := readRequest(t, candidate)
	request.PayloadSHA256 = catalogv1.DigestBytes(payload)
	request.Objects[0].Path = manifest.Artifacts[0].Path
	writeJSONFile(t, filepath.Join(candidate, "signing-request.json"), request, 0o644)
	provider := newMemoryProvider("test-a", 0x72)
	if _, err := Sign(candidate, provider); err == nil || !strings.Contains(err.Error(), "path is not canonical") {
		t.Fatalf("coherent noncanonical path reached wrong check: %v", err)
	}
	if provider.calls != 0 {
		t.Fatal("provider signed noncanonical object path")
	}
}

func TestPreparedCandidatePinsValidatedBytes(t *testing.T) {
	candidate := copyCandidate(t)
	payload, err := os.ReadFile(filepath.Join(candidate, "manifest.payload.json"))
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := Prepare(candidate)
	if err != nil {
		t.Fatal(err)
	}
	inspection := prepared.Inspection()
	if inspection.RequestDigest == "" {
		t.Fatal("prepared candidate lacks request digest")
	}
	if err := os.WriteFile(filepath.Join(candidate, "manifest.payload.json"), []byte("replaced after prepare"), 0o644); err != nil {
		t.Fatal(err)
	}
	provider := newMemoryProvider("test-a", 0x61)
	fragment, err := prepared.Sign(provider)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(fragment.Signature)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := provider.private.Public().(ed25519.PublicKey)
	if !ed25519.Verify(publicKey, payload, signature) {
		t.Fatal("prepared candidate did not sign its pinned payload")
	}
	if ed25519.Verify(publicKey, []byte("replaced after prepare"), signature) {
		t.Fatal("prepared candidate signed replacement bytes")
	}
}

func TestInspectRejectsCandidateRootIdentityMismatch(t *testing.T) {
	candidate := copyCandidate(t)
	mismatched := filepath.Join(filepath.Dir(candidate), "other-source")
	if err := os.Rename(candidate, mismatched); err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(mismatched); err == nil {
		t.Fatal("candidate directory identity mismatch was accepted")
	}
}

func TestInspectRejectsSymlinkedCandidateRoot(t *testing.T) {
	candidate := copyCandidate(t)
	link := filepath.Join(t.TempDir(), "candidate-link")
	if err := os.Symlink(candidate, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(link); err == nil {
		t.Fatal("symlinked candidate root was accepted")
	}
}

func TestCandidateFileModeRejectsDevicesAndExecutables(t *testing.T) {
	for name, mode := range map[string]fs.FileMode{
		"device":     os.ModeDevice | 0o600,
		"named pipe": os.ModeNamedPipe | 0o600,
		"socket":     os.ModeSocket | 0o600,
		"symlink":    os.ModeSymlink | 0o777,
		"executable": 0o755,
	} {
		t.Run(name, func(t *testing.T) {
			if validCandidateFileMode(mode) {
				t.Fatalf("unsafe mode %s was accepted", mode)
			}
		})
	}
	if !validCandidateFileMode(0o644) {
		t.Fatal("regular non-executable file mode was rejected")
	}
}

func TestFragmentSetRejectsMixedRequestsAndDuplicateMaterial(t *testing.T) {
	candidate := copyCandidate(t)
	inspection, err := Inspect(candidate)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(filepath.Join(candidate, "manifest.payload.json"))
	if err != nil {
		t.Fatal(err)
	}
	first := newMemoryProvider("test-a", 0x21)
	second := newMemoryProvider("test-b", 0x22)
	firstFragment, err := Sign(candidate, first)
	if err != nil {
		t.Fatal(err)
	}
	secondFragment, err := Sign(candidate, second)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]ed25519.PublicKey{
		first.KeyID():  first.private.Public().(ed25519.PublicKey),
		second.KeyID(): second.private.Public().(ed25519.PublicKey),
	}
	if err := ValidateFragmentSet(payload, inspection.RequestDigest, []Fragment{firstFragment, secondFragment}, keys); err != nil {
		t.Fatalf("independent fragments rejected: %v", err)
	}

	mixed := secondFragment
	mixed.RequestDigest = catalogv1.DigestBytes([]byte("different request"))
	if err := ValidateFragmentSet(payload, inspection.RequestDigest, []Fragment{firstFragment, mixed}, keys); err == nil {
		t.Fatal("mixed request digests were accepted")
	}

	duplicate := newMemoryProvider("test-b", 0x21)
	duplicateFragment, err := Sign(candidate, duplicate)
	if err != nil {
		t.Fatal(err)
	}
	duplicateKeys := map[string]ed25519.PublicKey{
		first.KeyID():     first.private.Public().(ed25519.PublicKey),
		duplicate.KeyID(): duplicate.private.Public().(ed25519.PublicKey),
	}
	if err := ValidateFragmentSet(payload, inspection.RequestDigest, []Fragment{firstFragment, duplicateFragment}, duplicateKeys); err == nil {
		t.Fatal("two key IDs backed by the same material were accepted")
	}
}

func TestThreeTestProvidersProduceIndependentFragments(t *testing.T) {
	candidate := copyCandidate(t)
	seen := make(map[string]struct{})
	for index, marker := range []byte{0x31, 0x32, 0x33} {
		provider := newMemoryProvider("test-"+string(rune('a'+index)), marker)
		fragment, err := Sign(candidate, provider)
		if err != nil {
			t.Fatal(err)
		}
		if _, duplicate := seen[fragment.Signature]; duplicate {
			t.Fatal("test providers produced duplicate fragments")
		}
		seen[fragment.Signature] = struct{}{}
	}
}

func copyCandidate(t *testing.T) string {
	t.Helper()
	source := filepath.Join("..", "..", "fixtures", "v1", "candidate", "valid", "unlock-official-linux-amd64-static")
	destination := filepath.Join(t.TempDir(), "unlock-official-linux-amd64-static")
	if err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, content, 0o644)
	}); err != nil {
		t.Fatal(err)
	}
	return destination
}

func mutateRequest(t *testing.T, root string, mutate func(*catalogv1.SigningRequest)) {
	t.Helper()
	request := readRequest(t, root)
	mutate(&request)
	writeJSONFile(t, filepath.Join(root, "signing-request.json"), request, 0o644)
}

func readRequest(t *testing.T, root string) catalogv1.SigningRequest {
	t.Helper()
	var request catalogv1.SigningRequest
	decodeJSONFile(t, filepath.Join(root, "signing-request.json"), &request)
	return request
}

func decodeJSONFile(t *testing.T, path string, target any) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(content, target); err != nil {
		t.Fatal(err)
	}
}

func writeJSONFile(t *testing.T, path string, value any, mode fs.FileMode) {
	t.Helper()
	content, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatal(err)
	}
}

func firstObjectPath(t *testing.T, root string) string {
	t.Helper()
	request := readRequest(t, root)
	if len(request.Objects) == 0 {
		t.Fatal("fixture has no objects")
	}
	return filepath.Join(root, filepath.FromSlash(request.Objects[0].Path))
}

type treeSnapshot struct {
	path string
	mode fs.FileMode
	sum  [sha256.Size]byte
}

func snapshotTree(t *testing.T, root string) []treeSnapshot {
	t.Helper()
	var result []treeSnapshot
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		item := treeSnapshot{path: filepath.ToSlash(relative), mode: info.Mode()}
		if info.Mode().IsRegular() {
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			item.sum = sha256.Sum256(content)
		}
		result = append(result, item)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return result
}

func equalSnapshots(first, second []treeSnapshot) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}
