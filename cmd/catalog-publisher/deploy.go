package main

import (
	"bytes"
	"context"
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

	"github.com/holandyoung/unlock-catalog-publisher/internal/assemble"
	"github.com/holandyoung/unlock-catalog-publisher/internal/catalogv1"
	"github.com/holandyoung/unlock-catalog-publisher/internal/package"
	"github.com/holandyoung/unlock-catalog-publisher/internal/repository"
)

var deploySourceIDPattern = regexp.MustCompile("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

type releaseArtifact struct {
	SourceID       string
	Version        uint64
	RootVersion    uint64
	ManifestDigest string
	EnvelopeSHA256 string
	RootDigest     string
	Immutables     []repository.Object
	RootArchive    repository.Object
	LiveManifest   repository.Object
	LiveRoot       repository.Object
}

type deployReport struct {
	SourceID       string `json:"sourceId"`
	Version        uint64 `json:"version"`
	RootVersion    uint64 `json:"rootVersion"`
	ManifestDigest string `json:"manifestDigest"`
	EnvelopeSHA256 string `json:"envelopeSha256"`
	RootDigest     string `json:"rootDigest"`
	ObjectCount    int    `json:"objectCount"`
	ObjectBytes    int64  `json:"objectBytes"`
	LiveETag       string `json:"liveEtag"`
}

func deployRelease(ctx context.Context, store repository.ObjectStore, artifact releaseArtifact, expectedLiveETag *string) (deployReport, error) {
	if store == nil {
		return deployReport{}, fmt.Errorf("object store is required")
	}
	var total int64
	for _, object := range artifact.Immutables {
		if _, err := repository.PutImmutable(ctx, store, object); err != nil {
			return deployReport{}, err
		}
		total += int64(len(object.Body))
	}
	live, err := repository.CompareAndSwapLive(ctx, store, artifact.LiveManifest, expectedLiveETag)
	if err != nil {
		return deployReport{}, err
	}
	return deployReport{
		SourceID: artifact.SourceID, Version: artifact.Version, RootVersion: artifact.RootVersion,
		ManifestDigest: artifact.ManifestDigest, EnvelopeSHA256: artifact.EnvelopeSHA256,
		RootDigest: artifact.RootDigest, ObjectCount: len(artifact.Immutables),
		ObjectBytes: total, LiveETag: live.ETag,
	}, nil
}

func deployRoot(ctx context.Context, store repository.ObjectStore, artifact releaseArtifact, expectedLiveETag *string) (deployReport, error) {
	if store == nil {
		return deployReport{}, fmt.Errorf("object store is required")
	}
	if _, err := repository.PutImmutable(ctx, store, artifact.RootArchive); err != nil {
		return deployReport{}, err
	}
	live, err := repository.CompareAndSwapLive(ctx, store, artifact.LiveRoot, expectedLiveETag)
	if err != nil {
		return deployReport{}, err
	}
	return deployReport{
		SourceID: artifact.SourceID, Version: artifact.Version, RootVersion: artifact.RootVersion,
		ManifestDigest: artifact.ManifestDigest, EnvelopeSHA256: artifact.EnvelopeSHA256,
		RootDigest: artifact.RootDigest, ObjectCount: 1,
		ObjectBytes: int64(len(artifact.RootArchive.Body)), LiveETag: live.ETag,
	}, nil
}

func loadRelease(releaseRoot, prefix string) (releaseArtifact, error) {
	if err := validateReleaseRoot(releaseRoot); err != nil {
		return releaseArtifact{}, err
	}
	if err := validateKeyPrefix(prefix); err != nil {
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
	if !deploySourceIDPattern.MatchString(manifest.Signed.SourceID) || manifest.Signed.Version == 0 || signedRoot.Signed.Version == 0 {
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
	sourcePrefix := path.Join(prefix, manifest.Signed.SourceID)
	version := fmt.Sprintf("%020d", manifest.Signed.Version)
	rootVersion := fmt.Sprintf("%020d", signedRoot.Signed.Version)
	expectedPackageFiles := map[string][]byte{"manifest.json": manifestBytes, "root.json": rootBytes}
	expectedReleaseFiles := map[string][]byte{"manifest.json": manifestBytes, "root.json": rootBytes}
	immutables := make([]repository.Object, 0, len(manifest.Signed.Artifacts)+3)
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
		immutables = append(immutables, repository.Object{
			Key: path.Join(sourcePrefix, descriptor.Path), Body: content, ContentType: descriptor.MediaType,
		})
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
	rootArchiveObject := repository.Object{
		Key:  path.Join(sourcePrefix, "roots", rootVersion, rootDigest, "root.json"),
		Body: rootBytes, ContentType: "application/json",
	}
	immutables = append(immutables,
		repository.Object{
			Key:  path.Join(sourcePrefix, "archive", version, manifestDigest, "manifest.json"),
			Body: manifestBytes, ContentType: "application/json",
		},
		rootArchiveObject,
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
	if err := validateDeployPackageSize(len(packageBytes)); err != nil {
		return releaseArtifact{}, err
	}
	if err := packagefile.VerifyPackage(packagePaths[0], expectedPackageFiles); err != nil {
		return releaseArtifact{}, fmt.Errorf("verify release package: %w", err)
	}
	expectedReleaseFiles[packageName] = packageBytes
	immutables = append(immutables, repository.Object{
		Key:  path.Join(sourcePrefix, "packages", version, manifestDigest, packageName),
		Body: packageBytes, ContentType: "application/vnd.unlock.catalog-package+zip",
	})
	if err := validateExactReleaseTree(releaseRoot, expectedReleaseFiles); err != nil {
		return releaseArtifact{}, err
	}
	sort.Slice(immutables, func(i, j int) bool { return immutables[i].Key < immutables[j].Key })
	return releaseArtifact{
		SourceID: manifest.Signed.SourceID, Version: manifest.Signed.Version,
		RootVersion: signedRoot.Signed.Version, ManifestDigest: manifestDigest,
		EnvelopeSHA256: catalogv1.DigestBytes(manifestBytes), RootDigest: rootDigest,
		Immutables: immutables, RootArchive: rootArchiveObject,
		LiveManifest: repository.Object{
			Key: path.Join(sourcePrefix, "manifest.json"), Body: manifestBytes, ContentType: "application/json",
		},
		LiveRoot: repository.Object{
			Key: path.Join(sourcePrefix, "root.json"), Body: rootBytes, ContentType: "application/json",
		},
	}, nil
}

func validateDeployPackageSize(size int) error {
	if size > repository.MaxReadbackBytes {
		return fmt.Errorf("release package exceeds %d-byte readback limit", repository.MaxReadbackBytes)
	}
	return nil
}

func runDeploy(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("deploy", flag.ContinueOnError)
	flags.SetOutput(stderr)
	target := flags.String("target", "", "live pointer target: manifest or root")
	releaseRoot := flags.String("release", "", "assembled release directory")
	prefix := flags.String("prefix", "v1/sources", "bucket publication prefix")
	initialLive := flags.Bool("initial-live", false, "create an absent live pointer")
	expectedLiveETag := flags.String("expected-live-etag", "", "exact current live pointer ETag")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *releaseRoot == "" {
		return fmt.Errorf("deploy requires --target manifest|root --release DIR and no positional arguments")
	}
	if *target != "manifest" && *target != "root" {
		return fmt.Errorf("deploy target must be manifest or root")
	}
	if *initialLive == (*expectedLiveETag != "") {
		return fmt.Errorf("deploy requires exactly one of --initial-live or --expected-live-etag")
	}
	artifact, err := loadRelease(*releaseRoot, *prefix)
	if err != nil {
		return err
	}
	for _, name := range []string{"R2_ENDPOINT", "R2_BUCKET", "R2_ACCESS_KEY_ID", "R2_SECRET_ACCESS_KEY"} {
		if getenv(name) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	store, err := repository.NewR2Store(ctx, repository.R2Config{
		Endpoint: getenv("R2_ENDPOINT"), Bucket: getenv("R2_BUCKET"),
		AccessKeyID: getenv("R2_ACCESS_KEY_ID"), SecretAccessKey: getenv("R2_SECRET_ACCESS_KEY"),
	})
	if err != nil {
		return err
	}
	var expected *string
	if !*initialLive {
		expected = expectedLiveETag
	}
	var report deployReport
	switch *target {
	case "manifest":
		report, err = deployRelease(ctx, store, artifact, expected)
	case "root":
		report, err = deployRoot(ctx, store, artifact, expected)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(report)
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

func validateKeyPrefix(prefix string) error {
	if prefix == "" || path.IsAbs(prefix) || path.Clean(prefix) != prefix || prefix == "." ||
		strings.HasPrefix(prefix, "../") || strings.Contains(prefix, "\\") {
		return fmt.Errorf("unsafe publication prefix %q", prefix)
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
