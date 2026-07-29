package assemble

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/holandyoung/unlock-catalog/internal/catalogv1"
	"github.com/holandyoung/unlock-catalog/internal/package"
	"github.com/holandyoung/unlock-catalog/internal/signing"
)

type Options struct {
	CandidateDir       string
	OutputDir          string
	ExpectedSourceID   string
	GrantedPermissions []catalogv1.Permission
	CurrentRoot        TrustRoot
	PublishedRoot      SignedRoot
	PriorRevocations   []catalogv1.Revocation
	Now                time.Time
}

type SignedManifest struct {
	Signed     catalogv1.Manifest `json:"signed"`
	Signatures []Signature        `json:"signatures"`
}

type Release struct {
	Directory    string
	ManifestPath string
	RootPath     string
	ArchiveDir   string
	PackagePath  string
}

func Assemble(options Options, fragments []signing.Fragment) (Release, error) {
	if options.CandidateDir == "" || options.OutputDir == "" || options.ExpectedSourceID == "" {
		return Release{}, fmt.Errorf("candidate, output, and expected source identity are required")
	}
	if _, err := os.Lstat(options.OutputDir); err == nil {
		return Release{}, fmt.Errorf("release output already exists")
	} else if !os.IsNotExist(err) {
		return Release{}, err
	}
	inspection, err := signing.Inspect(options.CandidateDir)
	if err != nil {
		return Release{}, fmt.Errorf("candidate preflight: %w", err)
	}
	payload, err := os.ReadFile(filepath.Join(options.CandidateDir, "manifest.payload.json"))
	if err != nil {
		return Release{}, err
	}
	requestBytes, err := os.ReadFile(filepath.Join(options.CandidateDir, "signing-request.json"))
	if err != nil {
		return Release{}, err
	}
	if err := verifyCandidateReadback(inspection, requestBytes, payload); err != nil {
		return Release{}, err
	}
	var request catalogv1.SigningRequest
	if err := json.Unmarshal(requestBytes, &request); err != nil {
		return Release{}, fmt.Errorf("decode signing request: %w", err)
	}
	var manifest catalogv1.Manifest
	if err := json.Unmarshal(payload, &manifest); err != nil {
		return Release{}, fmt.Errorf("decode manifest payload: %w", err)
	}
	if request.SourceID != options.ExpectedSourceID || manifest.SourceID != options.ExpectedSourceID {
		return Release{}, fmt.Errorf("candidate source identity mismatch")
	}
	if !permissionSetsEqual(request.Permissions, options.GrantedPermissions) {
		return Release{}, fmt.Errorf("candidate permission set mismatch")
	}
	if request.PayloadSHA256 != catalogv1.DigestBytes(payload) || request.PayloadSHA256 != inspection.PayloadSHA256 {
		return Release{}, fmt.Errorf("candidate payload digest mismatch")
	}
	if manifest.Version != request.Version || !manifest.PublishedAt.Equal(request.PublishedAt) || !manifest.ExpiresAt.Equal(request.ExpiresAt) {
		return Release{}, fmt.Errorf("candidate manifest and request metadata differ")
	}
	if err := validateRevocationHistory(manifest.Revocations, options.PriorRevocations); err != nil {
		return Release{}, err
	}
	now := options.Now
	if now.IsZero() {
		now = manifest.PublishedAt
	}
	if err := verifySignedRoot(options.CurrentRoot, options.PublishedRoot, now); err != nil {
		return Release{}, fmt.Errorf("published root: %w", err)
	}
	if err := VerifyThreshold(payload, inspection.RequestDigest, fragments, options.CurrentRoot); err != nil {
		return Release{}, fmt.Errorf("current manifest root: %w", err)
	}
	if err := VerifyThreshold(payload, inspection.RequestDigest, fragments, options.PublishedRoot.Signed); err != nil {
		return Release{}, fmt.Errorf("next manifest root: %w", err)
	}
	signatures := make([]Signature, 0, len(fragments))
	for _, fragment := range fragments {
		signatures = append(signatures, Signature{KeyID: fragment.KeyID, Value: fragment.Signature})
	}
	sort.Slice(signatures, func(i, j int) bool { return signatures[i].KeyID < signatures[j].KeyID })
	manifestBytes, err := json.Marshal(SignedManifest{Signed: manifest, Signatures: signatures})
	if err != nil {
		return Release{}, err
	}
	rootBytes, err := json.Marshal(options.PublishedRoot)
	if err != nil {
		return Release{}, err
	}

	parent := filepath.Dir(options.OutputDir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return Release{}, err
	}
	staging, err := os.MkdirTemp(parent, ".catalog-release-*")
	if err != nil {
		return Release{}, err
	}
	defer os.RemoveAll(staging)
	expected := map[string][]byte{"manifest.json": manifestBytes, "root.json": rootBytes}
	if err := writeFile(staging, "manifest.json", manifestBytes); err != nil {
		return Release{}, err
	}
	if err := writeFile(staging, "root.json", rootBytes); err != nil {
		return Release{}, err
	}
	for _, object := range request.Objects {
		content, err := os.ReadFile(filepath.Join(options.CandidateDir, filepath.FromSlash(object.Path)))
		if err != nil {
			return Release{}, err
		}
		if err := verifyObjectReadback(object, content); err != nil {
			return Release{}, err
		}
		expected[object.Path] = content
		if err := writeFile(staging, object.Path, content); err != nil {
			return Release{}, err
		}
	}
	packageName := fmt.Sprintf("%s-v%020d.ucp", manifest.SourceID, manifest.Version)
	packagePath := filepath.Join(staging, packageName)
	if err := packagefile.BuildPackage(staging, packagePath, expected); err != nil {
		return Release{}, err
	}
	archiveRelative := filepath.Join("archive", fmt.Sprintf("%020d", manifest.Version))
	if err := writeFile(staging, filepath.Join(archiveRelative, "manifest.json"), manifestBytes); err != nil {
		return Release{}, err
	}
	if err := writeFile(staging, filepath.Join(archiveRelative, "root.json"), rootBytes); err != nil {
		return Release{}, err
	}
	if err := os.Rename(staging, options.OutputDir); err != nil {
		return Release{}, fmt.Errorf("publish release directory: %w", err)
	}
	return Release{
		Directory: options.OutputDir, ManifestPath: filepath.Join(options.OutputDir, "manifest.json"),
		RootPath: filepath.Join(options.OutputDir, "root.json"), ArchiveDir: filepath.Join(options.OutputDir, archiveRelative),
		PackagePath: filepath.Join(options.OutputDir, packageName),
	}, nil
}

func verifyCandidateReadback(inspection signing.Inspection, requestBytes, payload []byte) error {
	if catalogv1.DigestBytes(requestBytes) != inspection.RequestDigest {
		return fmt.Errorf("candidate signing request changed after preflight")
	}
	if catalogv1.DigestBytes(payload) != inspection.PayloadSHA256 {
		return fmt.Errorf("candidate manifest payload changed after preflight")
	}
	return nil
}

func verifyObjectReadback(object catalogv1.SigningObject, content []byte) error {
	if int64(len(content)) != object.Length || catalogv1.DigestBytes(content) != object.SHA256 {
		return fmt.Errorf("candidate object %q changed after preflight", object.ArtifactID)
	}
	return nil
}

func validateRevocationHistory(current, prior []catalogv1.Revocation) error {
	currentByID := make(map[string]catalogv1.Revocation, len(current))
	for _, revocation := range current {
		if _, duplicate := currentByID[revocation.RevocationID]; duplicate {
			return fmt.Errorf("duplicate revocation ID %q", revocation.RevocationID)
		}
		currentByID[revocation.RevocationID] = revocation
	}
	for _, old := range prior {
		next, ok := currentByID[old.RevocationID]
		if !ok {
			return fmt.Errorf("revocation %q was removed", old.RevocationID)
		}
		if next.Kind != old.Kind || next.TargetID != old.TargetID || next.Reason != old.Reason || next.Version < old.Version {
			return fmt.Errorf("revocation %q changed backwards", old.RevocationID)
		}
	}
	return nil
}

func permissionSetsEqual(left, right []catalogv1.Permission) bool {
	if len(left) != len(right) {
		return false
	}
	counts := make(map[catalogv1.Permission]int, len(left))
	for _, permission := range left {
		counts[permission]++
	}
	for _, permission := range right {
		counts[permission]--
	}
	for _, count := range counts {
		if count != 0 {
			return false
		}
	}
	return true
}

func writeFile(root, relative string, content []byte) error {
	clean := filepath.Clean(relative)
	if clean == "." || filepath.IsAbs(clean) || clean != relative || bytes.Contains([]byte(relative), []byte(".."+string(filepath.Separator))) {
		return fmt.Errorf("unsafe release path %q", relative)
	}
	destination := filepath.Join(root, relative)
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(destination, content, 0o644); err != nil {
		return err
	}
	return nil
}
