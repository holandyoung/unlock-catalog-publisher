package assemble

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/holandyoung/unlock-catalog/internal/catalogv1"
	"github.com/holandyoung/unlock-catalog/internal/signing"
)

const (
	fixtureGeneratorBaseCommit = "08855a6b339b7213248eba7ec4d1abf151da55fb"
	fixtureGeneratedAt         = "2026-07-30T05:20:00Z"
	fixtureGenerationCommand   = "UPDATE_FIXTURES=1 go test ./internal/assemble -run TestSignedFixturesMatchGenerated -count=1"
)

var fixtureGeneratorSources = []string{
	"internal/assemble/assembler.go",
	"internal/assemble/conformance_fixtures_test.go",
	"internal/assemble/fixtures_test.go",
	"internal/assemble/root.go",
	"internal/catalogv1/types.go",
	"internal/package/package.go",
}

func generateConformanceNegativeFixtures(t *testing.T, output string, dataManifestBytes []byte) {
	t.Helper()
	positiveData := filepath.Join(output, "positive", "data")
	positiveExec := filepath.Join(output, "positive", "exec")
	dataRootBytes := mustRead(t, filepath.Join(positiveData, "current-root.json"))
	dataMetadata := readSignedFixtureMetadata(t, filepath.Join(positiveData, "metadata.json"))
	execRootBytes := mustRead(t, filepath.Join(positiveExec, "current-root.json"))
	execManifestBytes := mustRead(t, filepath.Join(positiveExec, "release", "manifest.json"))
	execMetadata := readSignedFixtureMetadata(t, filepath.Join(positiveExec, "metadata.json"))

	badSignature := decodeSignedFixtureManifest(t, dataManifestBytes)
	signature, err := base64.StdEncoding.Strict().DecodeString(badSignature.Signatures[0].Value)
	if err != nil {
		t.Fatal(err)
	}
	signature[0] ^= 0x01
	badSignature.Signatures[0].Value = base64.StdEncoding.EncodeToString(signature)
	writeManifestNegative(t, output, "bad-signature", marshalFixtureJSON(t, badSignature), dataRootBytes,
		withExpectedFailure(dataMetadata, "signature"))

	var badRoot TrustRoot
	decodeFixtureJSON(t, dataRootBytes, &badRoot)
	badRoot.Threshold = len(badRoot.Keys) + 1
	writeManifestNegative(t, output, "bad-root", dataManifestBytes, marshalFixtureJSON(t, badRoot),
		withExpectedFailure(dataMetadata, "root"))

	badSource := withExpectedFailure(dataMetadata, "source-id")
	badSource.ExpectedSourceID = "different-conformance-source"
	writeManifestNegative(t, output, "bad-source-id", dataManifestBytes, dataRootBytes, badSource)

	badPermission := withExpectedFailure(execMetadata, "permission")
	badPermission.GrantedPermissions = []catalogv1.Permission{
		catalogv1.PermissionMetadata,
		catalogv1.PermissionDetectionData,
		catalogv1.PermissionRoutingData,
	}
	writeManifestNegative(t, output, "bad-permission", execManifestBytes, execRootBytes, badPermission)

	dataSigned := decodeSignedFixtureManifest(t, dataManifestBytes)
	descriptor := dataSigned.Signed.Artifacts[0]
	artifact := mustRead(t, filepath.Join(positiveData, "release", filepath.FromSlash(descriptor.Path)))
	badDigest := append([]byte(nil), artifact...)
	badDigest[0] ^= 0x01
	badDigestMetadata := withExpectedFailure(dataMetadata, "digest")
	badDigestMetadata.ArtifactID = descriptor.ArtifactID
	writeArtifactNegative(t, output, "bad-digest", dataManifestBytes, dataRootBytes, badDigestMetadata, badDigest)

	badLengthMetadata := withExpectedFailure(dataMetadata, "length")
	badLengthMetadata.ArtifactID = descriptor.ArtifactID
	writeArtifactNegative(t, output, "bad-length", dataManifestBytes, dataRootBytes, badLengthMetadata, artifact[:len(artifact)-1])

	badPathManifest := cloneFixtureManifest(t, dataSigned.Signed)
	badPathManifest.Artifacts[0].Path = "../escape"
	writeManifestNegative(t, output, "bad-path", resignFixtureManifest(t, badPathManifest, "data-a", "data-b"), dataRootBytes,
		withExpectedFailure(dataMetadata, "path"))

	badRevocationManifest := cloneFixtureManifest(t, dataSigned.Signed)
	badRevocationManifest.Revocations = []catalogv1.Revocation{{
		RevocationID: "future-revocation", Kind: "artifact", TargetID: descriptor.ArtifactID,
		Version: badRevocationManifest.Version + 1, Reason: "synthetic invalid future revocation",
	}}
	writeManifestNegative(t, output, "bad-revocation", resignFixtureManifest(t, badRevocationManifest, "data-a", "data-b"), dataRootBytes,
		withExpectedFailure(dataMetadata, "revocation"))

	badPackage := append([]byte(nil), mustRead(t, filepath.Join(positiveData, "release", "unlock-catalog-package-v1.tar.zst"))...)
	badPackage = append(badPackage, 0)
	packageRoot := filepath.Join(output, "negative", "bad-package")
	writeFixtureFile(t, packageRoot, "unlock-catalog-package-v1.tar.zst", badPackage)
	writeFixtureJSON(t, packageRoot, "metadata.json", withExpectedFailure(dataMetadata, "package"))
}

func writeManifestNegative(t *testing.T, output, name string, manifest, root []byte, metadata signedFixtureMetadata) {
	t.Helper()
	caseRoot := filepath.Join(output, "negative", name)
	writeFixtureFile(t, caseRoot, "manifest.json", manifest)
	writeFixtureFile(t, caseRoot, "current-root.json", root)
	writeFixtureJSON(t, caseRoot, "metadata.json", metadata)
}

func writeArtifactNegative(t *testing.T, output, name string, manifest, root []byte, metadata signedFixtureMetadata, artifact []byte) {
	t.Helper()
	writeManifestNegative(t, output, name, manifest, root, metadata)
	writeFixtureFile(t, filepath.Join(output, "negative", name), "artifact.bin", artifact)
}

func withExpectedFailure(metadata signedFixtureMetadata, failure string) signedFixtureMetadata {
	metadata.ExpectedFailure = failure
	metadata.ArtifactID = ""
	return metadata
}

func readSignedFixtureMetadata(t *testing.T, path string) signedFixtureMetadata {
	t.Helper()
	var metadata signedFixtureMetadata
	decodeFixtureJSON(t, mustRead(t, path), &metadata)
	return metadata
}

func decodeSignedFixtureManifest(t *testing.T, content []byte) SignedManifest {
	t.Helper()
	var signed SignedManifest
	decodeFixtureJSON(t, content, &signed)
	return signed
}

func decodeFixtureJSON(t *testing.T, content []byte, target any) {
	t.Helper()
	if err := json.Unmarshal(content, target); err != nil {
		t.Fatal(err)
	}
}

func marshalFixtureJSON(t *testing.T, value any) []byte {
	t.Helper()
	content, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func cloneFixtureManifest(t *testing.T, manifest catalogv1.Manifest) catalogv1.Manifest {
	t.Helper()
	var clone catalogv1.Manifest
	decodeFixtureJSON(t, marshalFixtureJSON(t, manifest), &clone)
	return clone
}

func resignFixtureManifest(t *testing.T, manifest catalogv1.Manifest, keyIDs ...string) []byte {
	t.Helper()
	payload := marshalFixtureJSON(t, manifest)
	keys := testKeys(t, "data-a", "data-b", "data-c", "data-d")
	signatures := make([]Signature, 0, len(keyIDs))
	for _, keyID := range keyIDs {
		key, ok := keys[keyID]
		if !ok {
			t.Fatalf("unknown fixture signing key %q", keyID)
		}
		signatures = append(signatures, Signature{
			KeyID: keyID,
			Value: base64.StdEncoding.EncodeToString(ed25519.Sign(key.private, payload)),
		})
	}
	sort.Slice(signatures, func(i, j int) bool { return signatures[i].KeyID < signatures[j].KeyID })
	return marshalFixtureJSON(t, SignedManifest{Signed: manifest, Signatures: signatures})
}

func generateFixtureProvenance(t *testing.T, generatedRoot string) {
	t.Helper()
	files := fixtureTree(t, filepath.Join(generatedRoot, "signed"))
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	var setInput strings.Builder
	var fileRows strings.Builder
	for _, name := range names {
		digest := digestFixtureBytes(files[name])
		fmt.Fprintf(&setInput, "signed/%s\t%d\t%s\n", name, len(files[name]), digest)
		fmt.Fprintf(&fileRows, "| %s | %d | %s |\n", markdownCode("signed/"+name), len(files[name]), markdownCode(digest))
	}

	var sourceRows strings.Builder
	for _, name := range fixtureGeneratorSources {
		content := mustRead(t, filepath.Join("..", "..", filepath.FromSlash(name)))
		fmt.Fprintf(&sourceRows, "| %s | %s |\n", markdownCode(name), markdownCode(digestFixtureBytes(content)))
	}

	var provenance strings.Builder
	fmt.Fprintln(&provenance, "# Catalog V1 conformance fixture provenance")
	fmt.Fprintln(&provenance)
	fmt.Fprintln(&provenance, "This file describes public, synthetic, test-only fixtures. It contains no private key or production authorization material.")
	fmt.Fprintln(&provenance)
	fmt.Fprintf(&provenance, "- Protocol version: %s\n", markdownCode("unlock-catalog-v1"))
	fmt.Fprintf(&provenance, "- Generator base commit: %s\n", markdownCode(fixtureGeneratorBaseCommit))
	fmt.Fprintf(&provenance, "- Generation command: %s\n", markdownCode(fixtureGenerationCommand))
	fmt.Fprintf(&provenance, "- Generated at: %s\n", markdownCode(fixtureGeneratedAt))
	fmt.Fprintf(&provenance, "- Fixed verification time: %s\n", markdownCode("2026-07-29T09:00:00Z"))
	fmt.Fprintf(&provenance, "- Earliest manifest expiry: %s\n", markdownCode("2026-08-12T08:00:00Z"))
	fmt.Fprintf(&provenance, "- Fixture-set digest: %s\n", markdownCode(digestFixtureBytes([]byte(setInput.String()))))
	fmt.Fprintf(&provenance, "- Fixture-set digest algorithm: SHA256 of sorted %s records below; this provenance file is excluded.\n",
		markdownCode("path<TAB>length<TAB>sha256<LF>"))
	fmt.Fprintln(&provenance)
	fmt.Fprintln(&provenance, "The final Catalog task commit cannot be embedded here without a self-reference. The consuming platform fixture record pins both the Catalog task commit and merge commit after this tree is merged.")
	fmt.Fprintln(&provenance)
	fmt.Fprintln(&provenance, "## Generator sources")
	fmt.Fprintln(&provenance)
	fmt.Fprintln(&provenance, "| Path | SHA256 |")
	fmt.Fprintln(&provenance, "| :--- | :--- |")
	provenance.WriteString(sourceRows.String())
	fmt.Fprintln(&provenance)
	fmt.Fprintln(&provenance, "## Fixture files")
	fmt.Fprintln(&provenance)
	fmt.Fprintln(&provenance, "| Path | Length | SHA256 |")
	fmt.Fprintln(&provenance, "| :--- | ---: | :--- |")
	provenance.WriteString(fileRows.String())
	writeFixtureFile(t, generatedRoot, "PROVENANCE.md", []byte(provenance.String()))
}

func markdownCode(value string) string {
	return "`" + value + "`"
}

func digestFixtureBytes(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func verifyFixtureThreshold(t *testing.T, signed SignedManifest, root TrustRoot) error {
	t.Helper()
	payload := marshalFixtureJSON(t, signed.Signed)
	requestDigest := catalogv1.DigestBytes(payload)
	fragments := make([]signing.Fragment, 0, len(signed.Signatures))
	for _, signature := range signed.Signatures {
		fragments = append(fragments, signing.Fragment{
			RequestDigest: requestDigest,
			KeyID:         signature.KeyID,
			Signature:     signature.Value,
		})
	}
	return VerifyThreshold(payload, requestDigest, fragments, root)
}

func TestGeneratedNegativeFixturesIsolateExpectedFailures(t *testing.T) {
	root := filepath.Join(t.TempDir(), "signed")
	dataManifest := generateSignedFixture(t, root, "data", "unlock-official-linux-amd64-static", []string{"data-a", "data-b", "data-c", "data-d"})
	generateSignedFixture(t, root, "exec", "unlock-official-linux-amd64-static-exec", []string{"exec-a", "exec-b", "exec-c", "exec-d"})
	generateConformanceNegativeFixtures(t, root, dataManifest)

	for _, name := range []string{"bad-signature", "bad-root", "bad-source-id", "bad-permission", "bad-digest", "bad-length", "bad-path", "bad-revocation", "bad-package"} {
		metadata := readSignedFixtureMetadata(t, filepath.Join(root, "negative", name, "metadata.json"))
		if metadata.ExpectedFailure == "" {
			t.Fatalf("negative fixture %q has no expected failure", name)
		}
		if !metadata.VerifyAt.Equal(time.Date(2026, 7, 29, 9, 0, 0, 0, time.UTC)) {
			t.Fatalf("negative fixture %q verification time drifted", name)
		}
	}

	badPath := decodeSignedFixtureManifest(t, mustRead(t, filepath.Join(root, "negative", "bad-path", "manifest.json")))
	if got := badPath.Signed.Artifacts[0].Path; got != "../escape" || len(badPath.Signed.Revocations) != 0 {
		t.Fatalf("bad-path mutation leaked: path=%q revocations=%d", got, len(badPath.Signed.Revocations))
	}
	var dataRoot TrustRoot
	decodeFixtureJSON(t, mustRead(t, filepath.Join(root, "positive", "data", "current-root.json")), &dataRoot)
	if err := verifyFixtureThreshold(t, badPath, dataRoot); err != nil {
		t.Fatalf("bad-path signature must remain valid: %v", err)
	}
	badRevocation := decodeSignedFixtureManifest(t, mustRead(t, filepath.Join(root, "negative", "bad-revocation", "manifest.json")))
	if got := badRevocation.Signed.Artifacts[0].Path; got == "../escape" || len(badRevocation.Signed.Revocations) != 1 ||
		badRevocation.Signed.Revocations[0].Version <= badRevocation.Signed.Version {
		t.Fatalf("bad-revocation is not isolated: path=%q revocations=%v", got, badRevocation.Signed.Revocations)
	}
	if err := verifyFixtureThreshold(t, badRevocation, dataRoot); err != nil {
		t.Fatalf("bad-revocation signature must remain valid: %v", err)
	}
	badSignature := decodeSignedFixtureManifest(t, mustRead(t, filepath.Join(root, "negative", "bad-signature", "manifest.json")))
	if err := verifyFixtureThreshold(t, badSignature, dataRoot); err == nil {
		t.Fatal("bad-signature fixture still meets its threshold")
	}

	var badRoot TrustRoot
	decodeFixtureJSON(t, mustRead(t, filepath.Join(root, "negative", "bad-root", "current-root.json")), &badRoot)
	if _, err := validateRoot(badRoot); err == nil {
		t.Fatal("bad-root fixture is structurally valid")
	}

	descriptor := badPath.Signed.Artifacts[0]
	badDigest := mustRead(t, filepath.Join(root, "negative", "bad-digest", "artifact.bin"))
	if int64(len(badDigest)) != descriptor.Length || catalogv1.DigestBytes(badDigest) == descriptor.SHA256 {
		t.Fatal("bad-digest fixture does not isolate a same-length digest mismatch")
	}
	badLength := mustRead(t, filepath.Join(root, "negative", "bad-length", "artifact.bin"))
	if int64(len(badLength)) == descriptor.Length {
		t.Fatal("bad-length fixture still has the declared length")
	}

	positivePackage := mustRead(t, filepath.Join(root, "positive", "data", "release", "unlock-catalog-package-v1.tar.zst"))
	badPackage := mustRead(t, filepath.Join(root, "negative", "bad-package", "unlock-catalog-package-v1.tar.zst"))
	if len(badPackage) != len(positivePackage)+1 || !bytes.Equal(badPackage[:len(positivePackage)], positivePackage) {
		t.Fatal("bad-package fixture is not an isolated trailing-byte mutation")
	}
}
