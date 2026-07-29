package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/holandyoung/unlock-catalog/internal/assemble"
	"github.com/holandyoung/unlock-catalog/internal/catalogv1"
	"github.com/holandyoung/unlock-catalog/internal/package"
	"github.com/holandyoung/unlock-catalog/internal/repository"
	"github.com/holandyoung/unlock-catalog/internal/signing"
)

var releaseSourceIDPattern = regexp.MustCompile("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

type releaseArtifact struct {
	SourceID       string
	Version        uint64
	RootVersion    uint64
	ManifestDigest string
	EnvelopeSHA256 string
	RootDigest     string
	Files          []repository.File
}

type releaseReport struct {
	SourceID       string `json:"sourceId"`
	Version        uint64 `json:"version"`
	RootVersion    uint64 `json:"rootVersion"`
	ManifestDigest string `json:"manifestDigest"`
	EnvelopeSHA256 string `json:"envelopeSha256"`
	RootDigest     string `json:"rootDigest"`
	FileCount      int    `json:"fileCount"`
	FileBytes      int64  `json:"fileBytes"`
}

type publishedRelease struct {
	manifest      assemble.SignedManifest
	root          assemble.SignedRoot
	manifestBytes []byte
	rootBytes     []byte
}

func materializeRelease(repositoryRoot string, artifact releaseArtifact) (releaseReport, error) {
	result, err := repository.MaterializeRelease(repositoryRoot, repository.Release{
		SourceID: artifact.SourceID,
		Files:    artifact.Files,
	})
	if err != nil {
		return releaseReport{}, err
	}
	return releaseReport{
		SourceID: artifact.SourceID, Version: artifact.Version, RootVersion: artifact.RootVersion,
		ManifestDigest: artifact.ManifestDigest, EnvelopeSHA256: artifact.EnvelopeSHA256,
		RootDigest: artifact.RootDigest, FileCount: result.FileCount, FileBytes: result.FileBytes,
	}, nil
}

func loadRelease(releaseRoot string) (releaseArtifact, error) {
	if err := validateReleaseRoot(releaseRoot); err != nil {
		return releaseArtifact{}, err
	}
	manifestBytes, err := readReleaseFile(releaseRoot, "manifest.json")
	if err != nil {
		return releaseArtifact{}, err
	}
	rootBytes, err := readReleaseFile(releaseRoot, "root.json")
	if err != nil {
		return releaseArtifact{}, err
	}
	var manifest assemble.SignedManifest
	if err := decodeStrictJSON(manifestBytes, &manifest); err != nil {
		return releaseArtifact{}, fmt.Errorf("decode signed manifest: %w", err)
	}
	var signedRoot assemble.SignedRoot
	if err := decodeStrictJSON(rootBytes, &signedRoot); err != nil {
		return releaseArtifact{}, fmt.Errorf("decode signed root: %w", err)
	}
	if !releaseSourceIDPattern.MatchString(manifest.Signed.SourceID) || manifest.Signed.Version == 0 || signedRoot.Signed.Version == 0 {
		return releaseArtifact{}, fmt.Errorf("release source or version is invalid")
	}
	manifestDigest, canonicalManifest, err := catalogv1.ManifestDigest(manifest.Signed)
	if err != nil {
		return releaseArtifact{}, fmt.Errorf("canonical manifest: %w", err)
	}
	if len(canonicalManifest) == 0 {
		return releaseArtifact{}, fmt.Errorf("canonical manifest is empty")
	}
	rootPayload, err := json.Marshal(signedRoot.Signed)
	if err != nil {
		return releaseArtifact{}, fmt.Errorf("canonical root: %w", err)
	}
	rootDigest := catalogv1.DigestBytes(rootPayload)
	if err := verifySignedBytes(rootPayload, signedRoot.Signatures, signedRoot.Signed); err != nil {
		return releaseArtifact{}, fmt.Errorf("verify signed root: %w", err)
	}
	if err := verifySignedBytes(canonicalManifest, manifest.Signatures, signedRoot.Signed); err != nil {
		return releaseArtifact{}, fmt.Errorf("verify signed manifest: %w", err)
	}
	sourcePrefix := path.Join(repository.ReleasePrefix, manifest.Signed.SourceID)
	version := fmt.Sprintf("%020d", manifest.Signed.Version)
	rootVersion := fmt.Sprintf("%020d", signedRoot.Signed.Version)
	expectedPackageFiles := map[string][]byte{"manifest.json": manifestBytes, "root.json": rootBytes}
	expectedReleaseFiles := map[string][]byte{"manifest.json": manifestBytes, "root.json": rootBytes}
	files := make([]repository.File, 0, len(manifest.Signed.Artifacts)+5)
	seenObjects := make(map[string]struct{}, len(manifest.Signed.Artifacts))
	for _, descriptor := range manifest.Signed.Artifacts {
		if _, duplicate := seenObjects[descriptor.Path]; duplicate {
			return releaseArtifact{}, fmt.Errorf("duplicate release object path %q", descriptor.Path)
		}
		seenObjects[descriptor.Path] = struct{}{}
		content, err := readReleaseFile(releaseRoot, descriptor.Path)
		if err != nil {
			return releaseArtifact{}, err
		}
		if int64(len(content)) != descriptor.Length || catalogv1.DigestBytes(content) != descriptor.SHA256 {
			return releaseArtifact{}, fmt.Errorf("release object %q digest or length differs", descriptor.ArtifactID)
		}
		expectedPackageFiles[descriptor.Path] = content
		expectedReleaseFiles[descriptor.Path] = content
		files = append(files, repository.File{Path: path.Join(sourcePrefix, descriptor.Path), Body: content})
	}
	archiveManifest := path.Join("archive", version, "manifest.json")
	archiveRoot := path.Join("archive", version, "root.json")
	if content, err := readReleaseFile(releaseRoot, archiveManifest); err != nil || !bytes.Equal(content, manifestBytes) {
		return releaseArtifact{}, fmt.Errorf("release archive manifest differs")
	}
	if content, err := readReleaseFile(releaseRoot, archiveRoot); err != nil || !bytes.Equal(content, rootBytes) {
		return releaseArtifact{}, fmt.Errorf("release archive root differs")
	}
	expectedReleaseFiles[archiveManifest] = manifestBytes
	expectedReleaseFiles[archiveRoot] = rootBytes
	files = append(files,
		repository.File{
			Path: path.Join(sourcePrefix, "archive", version, manifestDigest, "manifest.json"),
			Body: manifestBytes,
		},
		repository.File{
			Path: path.Join(sourcePrefix, "roots", rootVersion, rootDigest, "root.json"),
			Body: rootBytes,
		},
	)
	packagePaths, err := filepath.Glob(filepath.Join(releaseRoot, "*.ucp"))
	if err != nil || len(packagePaths) != 1 {
		return releaseArtifact{}, fmt.Errorf("release requires exactly one .ucp package")
	}
	packageName := filepath.Base(packagePaths[0])
	packageBytes, err := readReleaseFile(releaseRoot, packageName)
	if err != nil {
		return releaseArtifact{}, err
	}
	if len(packageBytes) > repository.MaxReleaseFileBytes {
		return releaseArtifact{}, fmt.Errorf("release package exceeds %d-byte limit", repository.MaxReleaseFileBytes)
	}
	if err := packagefile.VerifyPackage(packagePaths[0], expectedPackageFiles); err != nil {
		return releaseArtifact{}, fmt.Errorf("verify release package: %w", err)
	}
	expectedReleaseFiles[packageName] = packageBytes
	files = append(files,
		repository.File{
			Path: path.Join(sourcePrefix, "packages", version, manifestDigest, packageName),
			Body: packageBytes,
		},
		repository.File{Path: path.Join(sourcePrefix, "manifest.json"), Body: manifestBytes},
		repository.File{Path: path.Join(sourcePrefix, "root.json"), Body: rootBytes},
	)
	if err := validateExactReleaseTree(releaseRoot, expectedReleaseFiles); err != nil {
		return releaseArtifact{}, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return releaseArtifact{
		SourceID: manifest.Signed.SourceID, Version: manifest.Signed.Version,
		RootVersion: signedRoot.Signed.Version, ManifestDigest: manifestDigest,
		EnvelopeSHA256: catalogv1.DigestBytes(manifestBytes), RootDigest: rootDigest,
		Files: files,
	}, nil
}

func runMaterialize(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("materialize", flag.ContinueOnError)
	flags.SetOutput(stderr)
	releaseRoot := flags.String("release", "", "assembled release directory")
	repositoryRoot := flags.String("repository", ".", "clean Catalog repository worktree")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *releaseRoot == "" {
		return fmt.Errorf("materialize requires --release DIR and no positional arguments")
	}
	artifact, err := loadRelease(*releaseRoot)
	if err != nil {
		return err
	}
	report, err := materializeRelease(*repositoryRoot, artifact)
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(report)
}

func runVerifyRelease(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("verify-release", flag.ContinueOnError)
	flags.SetOutput(stderr)
	baseRoot := flags.String("base", "", "base repository checkout")
	repositoryRoot := flags.String("repository", ".", "candidate repository checkout")
	var changedFiles stringList
	flags.Var(&changedFiles, "changed-file", "changed path relative to the repository root; repeat for every path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *baseRoot == "" {
		return fmt.Errorf("verify-release requires --base DIR and no positional arguments")
	}
	releaseChanged := true
	if len(changedFiles) != 0 {
		var err error
		releaseChanged, err = repository.ValidateReleaseChangePaths(changedFiles)
		if err != nil {
			return err
		}
	}
	if releaseChanged {
		if err := repository.VerifyReleaseDiff(*baseRoot, *repositoryRoot); err != nil {
			return err
		}
		baseReleases, err := verifyPublishedRepository(*baseRoot)
		if err != nil {
			return fmt.Errorf("verify base releases: %w", err)
		}
		candidateReleases, err := verifyPublishedRepository(*repositoryRoot)
		if err != nil {
			return err
		}
		if err := verifyForwardOnly(baseReleases, candidateReleases); err != nil {
			return err
		}
	}
	return json.NewEncoder(stdout).Encode(struct {
		Verified       bool `json:"verified"`
		ReleaseChanged bool `json:"releaseChanged"`
	}{Verified: true, ReleaseChanged: releaseChanged})
}

func verifyPublishedRepository(repositoryRoot string) (map[string]publishedRelease, error) {
	prefixRoot := filepath.Join(repositoryRoot, filepath.FromSlash(repository.ReleasePrefix))
	entries, err := os.ReadDir(prefixRoot)
	if os.IsNotExist(err) {
		return map[string]publishedRelease{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read signed release tree: %w", err)
	}
	releases := make(map[string]publishedRelease)
	for _, entry := range entries {
		if entry.Name() == "README.md" {
			continue
		}
		if !entry.IsDir() || !releaseSourceIDPattern.MatchString(entry.Name()) {
			return nil, fmt.Errorf("invalid signed release source %q", entry.Name())
		}
		release, err := verifyPublishedSource(filepath.Join(prefixRoot, entry.Name()), entry.Name())
		if err != nil {
			return nil, fmt.Errorf("verify signed release %q: %w", entry.Name(), err)
		}
		releases[entry.Name()] = release
	}
	return releases, nil
}

func verifyPublishedSource(sourceRoot, sourceID string) (publishedRelease, error) {
	manifestBytes, err := readReleaseFile(sourceRoot, "manifest.json")
	if err != nil {
		return publishedRelease{}, err
	}
	rootBytes, err := readReleaseFile(sourceRoot, "root.json")
	if err != nil {
		return publishedRelease{}, err
	}
	var manifest assemble.SignedManifest
	if err := decodeStrictJSON(manifestBytes, &manifest); err != nil {
		return publishedRelease{}, fmt.Errorf("decode live manifest: %w", err)
	}
	var signedRoot assemble.SignedRoot
	if err := decodeStrictJSON(rootBytes, &signedRoot); err != nil {
		return publishedRelease{}, fmt.Errorf("decode live root: %w", err)
	}
	if manifest.Signed.SourceID != sourceID || manifest.Signed.Version == 0 || signedRoot.Signed.Version == 0 {
		return publishedRelease{}, fmt.Errorf("live source identity or version differs")
	}
	manifestDigest, canonicalManifest, err := catalogv1.ManifestDigest(manifest.Signed)
	if err != nil {
		return publishedRelease{}, fmt.Errorf("canonical live manifest: %w", err)
	}
	rootPayload, err := json.Marshal(signedRoot.Signed)
	if err != nil {
		return publishedRelease{}, fmt.Errorf("canonical live root: %w", err)
	}
	rootDigest := catalogv1.DigestBytes(rootPayload)
	if err := verifySignedBytes(rootPayload, signedRoot.Signatures, signedRoot.Signed); err != nil {
		return publishedRelease{}, fmt.Errorf("verify live root: %w", err)
	}
	if err := verifySignedBytes(canonicalManifest, manifest.Signatures, signedRoot.Signed); err != nil {
		return publishedRelease{}, fmt.Errorf("verify live manifest: %w", err)
	}
	version := fmt.Sprintf("%020d", manifest.Signed.Version)
	rootVersion := fmt.Sprintf("%020d", signedRoot.Signed.Version)

	manifestArchive := path.Join("archive", version, manifestDigest, "manifest.json")
	archivedManifest, err := readReleaseFile(sourceRoot, manifestArchive)
	if err != nil || !bytes.Equal(archivedManifest, manifestBytes) {
		return publishedRelease{}, fmt.Errorf("live manifest lacks its exact immutable archive")
	}
	rootArchive := path.Join("roots", rootVersion, rootDigest, "root.json")
	archivedRoot, err := readReleaseFile(sourceRoot, rootArchive)
	if err != nil || !bytes.Equal(archivedRoot, rootBytes) {
		return publishedRelease{}, fmt.Errorf("live root lacks its exact immutable archive")
	}

	expectedPackageFiles := map[string][]byte{"manifest.json": manifestBytes, "root.json": rootBytes}
	seenObjects := make(map[string]struct{}, len(manifest.Signed.Artifacts))
	for _, descriptor := range manifest.Signed.Artifacts {
		if _, duplicate := seenObjects[descriptor.Path]; duplicate {
			return publishedRelease{}, fmt.Errorf("live manifest repeats object path %q", descriptor.Path)
		}
		seenObjects[descriptor.Path] = struct{}{}
		content, err := readReleaseFile(sourceRoot, descriptor.Path)
		if err != nil {
			return publishedRelease{}, fmt.Errorf("read live object %q: %w", descriptor.ArtifactID, err)
		}
		if int64(len(content)) != descriptor.Length || catalogv1.DigestBytes(content) != descriptor.SHA256 {
			return publishedRelease{}, fmt.Errorf("live object %q digest or length differs", descriptor.ArtifactID)
		}
		expectedPackageFiles[descriptor.Path] = content
	}
	packagePattern := filepath.Join(sourceRoot, "packages", version, manifestDigest, "*.ucp")
	packagePaths, err := filepath.Glob(packagePattern)
	if err != nil || len(packagePaths) != 1 {
		return publishedRelease{}, fmt.Errorf("live release requires exactly one matching immutable package")
	}
	if err := packagefile.VerifyPackage(packagePaths[0], expectedPackageFiles); err != nil {
		return publishedRelease{}, fmt.Errorf("verify live package: %w", err)
	}
	return publishedRelease{
		manifest: manifest, root: signedRoot,
		manifestBytes: manifestBytes, rootBytes: rootBytes,
	}, nil
}

func verifyForwardOnly(base, candidate map[string]publishedRelease) error {
	for sourceID, prior := range base {
		next, ok := candidate[sourceID]
		if !ok {
			return fmt.Errorf("published source %q was deleted", sourceID)
		}
		if next.manifest.Signed.Version < prior.manifest.Signed.Version ||
			(next.manifest.Signed.Version == prior.manifest.Signed.Version && !bytes.Equal(next.manifestBytes, prior.manifestBytes)) {
			return fmt.Errorf("published source %q manifest did not advance monotonically", sourceID)
		}
		if next.root.Signed.Version < prior.root.Signed.Version ||
			(next.root.Signed.Version == prior.root.Signed.Version && !bytes.Equal(next.rootBytes, prior.rootBytes)) {
			return fmt.Errorf("published source %q root did not advance monotonically", sourceID)
		}
		if !bytes.Equal(next.rootBytes, prior.rootBytes) {
			rootPayload, err := json.Marshal(next.root.Signed)
			if err != nil {
				return fmt.Errorf("published source %q canonical next root: %w", sourceID, err)
			}
			if err := verifySignedBytes(rootPayload, next.root.Signatures, prior.root.Signed); err != nil {
				return fmt.Errorf("published source %q next root lacks the prior threshold: %w", sourceID, err)
			}
			manifestPayload, err := catalogv1.CanonicalManifest(next.manifest.Signed)
			if err != nil {
				return fmt.Errorf("published source %q canonical next manifest: %w", sourceID, err)
			}
			if err := verifySignedBytes(manifestPayload, next.manifest.Signatures, prior.root.Signed); err != nil {
				return fmt.Errorf("published source %q next manifest lacks the prior threshold: %w", sourceID, err)
			}
		}
		if err := verifyRevocationsForward(prior.manifest.Signed.Revocations, next.manifest.Signed.Revocations); err != nil {
			return fmt.Errorf("published source %q: %w", sourceID, err)
		}
	}
	return nil
}

func verifyRevocationsForward(prior, next []catalogv1.Revocation) error {
	nextByID := make(map[string]catalogv1.Revocation, len(next))
	for _, revocation := range next {
		if _, duplicate := nextByID[revocation.RevocationID]; duplicate {
			return fmt.Errorf("duplicate revocation ID %q", revocation.RevocationID)
		}
		nextByID[revocation.RevocationID] = revocation
	}
	for _, old := range prior {
		current, ok := nextByID[old.RevocationID]
		if !ok {
			return fmt.Errorf("revocation %q was removed", old.RevocationID)
		}
		if current.Kind != old.Kind || current.TargetID != old.TargetID || current.Reason != old.Reason || current.Version < old.Version {
			return fmt.Errorf("revocation %q was weakened", old.RevocationID)
		}
	}
	return nil
}

func verifySignedBytes(payload []byte, signatures []assemble.Signature, root assemble.TrustRoot) error {
	requestDigest := catalogv1.DigestBytes(payload)
	fragments := make([]signing.Fragment, 0, len(signatures))
	seen := make(map[string]struct{}, len(signatures))
	for _, signature := range signatures {
		if _, duplicate := seen[signature.KeyID]; duplicate {
			return fmt.Errorf("duplicate signature key ID %q", signature.KeyID)
		}
		seen[signature.KeyID] = struct{}{}
		if _, trusted := root.Keys[signature.KeyID]; !trusted {
			continue
		}
		fragments = append(fragments, signing.Fragment{
			RequestDigest: requestDigest,
			KeyID:         signature.KeyID,
			Signature:     signature.Value,
		})
	}
	return assemble.VerifyThreshold(payload, requestDigest, fragments, root)
}

type stringList []string

func (values *stringList) String() string { return strings.Join(*values, ",") }

func (values *stringList) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func validateReleaseRoot(root string) error {
	if root == "" {
		return fmt.Errorf("release root is required")
	}
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("release root must be a real directory")
	}
	return nil
}

func readReleaseFile(root, relative string) ([]byte, error) {
	clean := path.Clean(relative)
	if clean != relative || clean == "." || path.IsAbs(clean) || strings.HasPrefix(clean, "../") || strings.Contains(relative, "\\") {
		return nil, fmt.Errorf("unsafe release path %q", relative)
	}
	filePath := filepath.Join(root, filepath.FromSlash(relative))
	info, err := os.Lstat(filePath)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o644 {
		return nil, fmt.Errorf("release path %q must be a mode 0644 regular file", relative)
	}
	return os.ReadFile(filePath)
}

func validateExactReleaseTree(root string, expected map[string][]byte) error {
	found := make(map[string]struct{}, len(expected))
	err := filepath.Walk(root, func(filePath string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, filePath)
		if err != nil {
			return err
		}
		if relative == "." || info.IsDir() {
			return nil
		}
		name := filepath.ToSlash(relative)
		if _, ok := expected[name]; !ok {
			return fmt.Errorf("release contains extra file %q", name)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o644 {
			return fmt.Errorf("release file %q has unsafe metadata", name)
		}
		found[name] = struct{}{}
		return nil
	})
	if err != nil {
		return err
	}
	if len(found) != len(expected) {
		return fmt.Errorf("release tree is missing expected files")
	}
	return nil
}

func decodeStrictJSON(content []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return fmt.Errorf("trailing JSON data: %w", err)
	}
	return nil
}
