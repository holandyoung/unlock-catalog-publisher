package assemble

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/holandyoung/unlock-catalog-publisher/internal/catalogv1"
	"github.com/holandyoung/unlock-catalog-publisher/internal/signing"
)

func TestVerifyThresholdRejectsUnsafeFragmentSets(t *testing.T) {
	payload := []byte(`{"catalog":"v1"}`)
	requestDigest := catalogv1.DigestBytes([]byte("request"))
	keys := testKeys(t, "a", "b", "c")
	root := testRoot(1, time.Now().UTC().Add(180*24*time.Hour), keys, "a", "b", "c")
	valid := []signing.Fragment{
		testFragment(payload, requestDigest, keys["a"]),
		testFragment(payload, requestDigest, keys["b"]),
	}

	tests := map[string]func() (TrustRoot, []signing.Fragment, []byte){
		"fewer than two unique keys": func() (TrustRoot, []signing.Fragment, []byte) {
			return root, valid[:1], payload
		},
		"duplicate public key material": func() (TrustRoot, []signing.Fragment, []byte) {
			bad := root
			bad.Keys = cloneKeys(root.Keys)
			bad.Keys["c"] = bad.Keys["b"]
			return bad, valid, payload
		},
		"mixed request digest": func() (TrustRoot, []signing.Fragment, []byte) {
			bad := append([]signing.Fragment(nil), valid...)
			bad[1].RequestDigest = catalogv1.DigestBytes([]byte("other request"))
			return root, bad, payload
		},
		"payload byte mutation": func() (TrustRoot, []signing.Fragment, []byte) {
			return root, valid, []byte(`{"catalog":"v2"}`)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidateRoot, fragments, candidatePayload := mutate()
			if err := VerifyThreshold(candidatePayload, requestDigest, fragments, candidateRoot); err == nil {
				t.Fatal("VerifyThreshold accepted unsafe fragments")
			}
		})
	}
	if err := VerifyThreshold(payload, requestDigest, valid, root); err != nil {
		t.Fatalf("VerifyThreshold valid 2-of-3 set: %v", err)
	}
}

func TestAssembleProducesImmutableReleaseWithoutMutatingCandidate(t *testing.T) {
	candidate := filepath.Join("..", "..", "fixtures", "v1", "candidate", "valid", "unlock-official-linux-amd64-static")
	payload := mustRead(t, filepath.Join(candidate, "manifest.payload.json"))
	request := mustRequest(t, candidate)
	manifest := mustManifest(t, payload)
	keys := testKeys(t, "a", "b", "c", "d")
	current := testRoot(1, manifest.PublishedAt.Add(200*24*time.Hour), keys, "a", "b", "c")
	next := testRoot(2, manifest.PublishedAt.Add(200*24*time.Hour), keys, "a", "b", "d")
	rootDigest, rootPayload := rootSigningPayload(t, next)
	signedRoot, err := AssembleSignedRoot(current, next, []signing.Fragment{
		testFragment(rootPayload, rootDigest, keys["a"]),
		testFragment(rootPayload, rootDigest, keys["b"]),
	}, manifest.PublishedAt)
	if err != nil {
		t.Fatalf("AssembleSignedRoot: %v", err)
	}
	fragments := []signing.Fragment{
		testFragment(payload, requestDigest(t, candidate), keys["a"]),
		testFragment(payload, requestDigest(t, candidate), keys["b"]),
	}
	before := snapshotTree(t, candidate)
	out := filepath.Join(t.TempDir(), "release")
	release, err := Assemble(Options{
		CandidateDir:       candidate,
		OutputDir:          out,
		ExpectedSourceID:   request.SourceID,
		GrantedPermissions: request.Permissions,
		CurrentRoot:        current,
		PublishedRoot:      signedRoot,
		Now:                manifest.PublishedAt,
	}, fragments)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if after := snapshotTree(t, candidate); !reflect.DeepEqual(after, before) {
		t.Fatal("assembler mutated candidate bytes")
	}
	for _, path := range []string{
		release.ManifestPath,
		release.RootPath,
		filepath.Join(release.ArchiveDir, "manifest.json"),
		filepath.Join(release.ArchiveDir, "root.json"),
		release.PackagePath,
	} {
		if info, statErr := os.Stat(path); statErr != nil || !info.Mode().IsRegular() {
			t.Fatalf("release output %q is not a regular file: %v", path, statErr)
		}
	}
	if got := mustRead(t, release.ManifestPath); len(got) == 0 || string(got) == string(payload) {
		t.Fatal("manifest.json must be a signed envelope, not the unsigned payload")
	}
	for _, object := range request.Objects {
		got := mustRead(t, filepath.Join(release.Directory, filepath.FromSlash(object.Path)))
		want := mustRead(t, filepath.Join(candidate, filepath.FromSlash(object.Path)))
		if string(got) != string(want) {
			t.Fatalf("object %q bytes changed", object.Path)
		}
	}
}

func TestAssembleRejectsIdentityPermissionAndRevocationDrift(t *testing.T) {
	candidate := filepath.Join("..", "..", "fixtures", "v1", "candidate", "valid", "unlock-official-linux-amd64-static")
	payload := mustRead(t, filepath.Join(candidate, "manifest.payload.json"))
	manifest := mustManifest(t, payload)
	request := mustRequest(t, candidate)
	keys := testKeys(t, "a", "b", "c", "d")
	current := testRoot(1, manifest.PublishedAt.Add(200*24*time.Hour), keys, "a", "b", "c")
	next := testRoot(2, manifest.PublishedAt.Add(200*24*time.Hour), keys, "a", "b", "d")
	rootDigest, rootPayload := rootSigningPayload(t, next)
	signedRoot, err := AssembleSignedRoot(current, next, []signing.Fragment{
		testFragment(rootPayload, rootDigest, keys["a"]),
		testFragment(rootPayload, rootDigest, keys["b"]),
	}, manifest.PublishedAt)
	if err != nil {
		t.Fatalf("AssembleSignedRoot: %v", err)
	}
	fragments := []signing.Fragment{
		testFragment(payload, requestDigest(t, candidate), keys["a"]),
		testFragment(payload, requestDigest(t, candidate), keys["b"]),
	}
	base := Options{
		CandidateDir: candidate, ExpectedSourceID: request.SourceID,
		GrantedPermissions: request.Permissions, CurrentRoot: current,
		PublishedRoot: signedRoot, Now: manifest.PublishedAt,
	}

	t.Run("source identity", func(t *testing.T) {
		options := base
		options.OutputDir = filepath.Join(t.TempDir(), "release")
		options.ExpectedSourceID = "other-source"
		if _, err := Assemble(options, fragments); err == nil {
			t.Fatal("Assemble accepted source identity drift")
		}
	})
	t.Run("permission set", func(t *testing.T) {
		options := base
		options.OutputDir = filepath.Join(t.TempDir(), "release")
		options.GrantedPermissions = append(append([]catalogv1.Permission(nil), request.Permissions...), catalogv1.PermissionExecutable)
		if _, err := Assemble(options, fragments); err == nil {
			t.Fatal("Assemble accepted permission drift")
		}
	})
	t.Run("revocation downgrade", func(t *testing.T) {
		options := base
		options.OutputDir = filepath.Join(t.TempDir(), "release")
		options.PriorRevocations = []catalogv1.Revocation{{
			RevocationID: "retired-key", Kind: "key", TargetID: "old-key", Version: 1, Reason: "retired",
		}}
		if _, err := Assemble(options, fragments); err == nil {
			t.Fatal("Assemble accepted removal of a prior revocation")
		}
	})
}

func TestCandidateReadbackRejectsRequestPayloadAndObjectDrift(t *testing.T) {
	requestBytes := []byte(`{"sourceId":"test-source"}`)
	payload := []byte(`{"protocol":"unlock-catalog-v1"}`)
	inspection := signing.Inspection{
		RequestDigest: catalogv1.DigestBytes(requestBytes),
		PayloadSHA256: catalogv1.DigestBytes(payload),
	}
	if err := verifyCandidateReadback(inspection, requestBytes, payload); err != nil {
		t.Fatalf("valid candidate readback: %v", err)
	}
	if err := verifyCandidateReadback(inspection, append(requestBytes, ' '), payload); err == nil {
		t.Fatal("candidate readback accepted request byte drift")
	}
	if err := verifyCandidateReadback(inspection, requestBytes, append(payload, ' ')); err == nil {
		t.Fatal("candidate readback accepted payload byte drift")
	}

	content := []byte("immutable object")
	descriptor := catalogv1.SigningObject{SHA256: catalogv1.DigestBytes(content), Length: int64(len(content))}
	if err := verifyObjectReadback(descriptor, content); err != nil {
		t.Fatalf("valid object readback: %v", err)
	}
	if err := verifyObjectReadback(descriptor, append(content, '!')); err == nil {
		t.Fatal("candidate readback accepted object byte drift")
	}
}

type testKey struct {
	id      string
	public  ed25519.PublicKey
	private ed25519.PrivateKey
}

func testKeys(t *testing.T, ids ...string) map[string]testKey {
	t.Helper()
	keys := make(map[string]testKey, len(ids))
	for _, id := range ids {
		seed := sha256.Sum256([]byte("UNLOCK CATALOG TEST ONLY KEY " + id))
		private := ed25519.NewKeyFromSeed(seed[:])
		keys[id] = testKey{id: id, public: private.Public().(ed25519.PublicKey), private: private}
	}
	return keys
}

func testRoot(version uint64, expires time.Time, keys map[string]testKey, ids ...string) TrustRoot {
	root := TrustRoot{Version: version, Threshold: 2, ExpiresAt: expires, Keys: make(map[string]string, len(ids))}
	for _, id := range ids {
		root.Keys[id] = base64.StdEncoding.EncodeToString(keys[id].public)
	}
	return root
}

func testFragment(payload []byte, requestDigest string, key testKey) signing.Fragment {
	return signing.Fragment{
		RequestDigest: requestDigest,
		KeyID:         key.id,
		Signature:     base64.StdEncoding.EncodeToString(ed25519.Sign(key.private, payload)),
	}
}

func rootSigningPayload(t *testing.T, root TrustRoot) (string, []byte) {
	t.Helper()
	payload, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return catalogv1.DigestBytes(payload), payload
}

func requestDigest(t *testing.T, candidate string) string {
	t.Helper()
	inspection, err := signing.Inspect(candidate)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	return inspection.RequestDigest
}

func mustRequest(t *testing.T, candidate string) catalogv1.SigningRequest {
	t.Helper()
	var request catalogv1.SigningRequest
	if err := json.Unmarshal(mustRead(t, filepath.Join(candidate, "signing-request.json")), &request); err != nil {
		t.Fatal(err)
	}
	return request
}

func mustManifest(t *testing.T, payload []byte) catalogv1.Manifest {
	t.Helper()
	var manifest catalogv1.Manifest
	if err := json.Unmarshal(payload, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func cloneKeys(keys map[string]string) map[string]string {
	copy := make(map[string]string, len(keys))
	for key, value := range keys {
		copy[key] = value
	}
	return copy
}

func snapshotTree(t *testing.T, root string) map[string][32]byte {
	t.Helper()
	snapshot := map[string][32]byte{}
	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		snapshot[filepath.ToSlash(relative)] = sha256.Sum256(content)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return snapshot
}
