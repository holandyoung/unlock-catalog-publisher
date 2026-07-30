// Package packagefile builds and verifies deterministic offline Catalog packages.
package packagefile

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
)

const (
	PackageFileName = "unlock-catalog-package-v1.tar.zst"
	PackageFormat   = "unlock-catalog-package-v1"

	maxCompressedBytes   = int64(256 << 20)
	maxUncompressedBytes = int64(256 << 20)
	maxArtifactBytes     = int64(64 << 20)
	maxManifestBytes     = int64(4 << 20)
	maxMembers           = 4096
	maxPathBytes         = 255
)

var (
	canonicalTime     = time.Unix(0, 0).UTC()
	digestPattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	sourceIDPattern   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	objectPathPattern = regexp.MustCompile(`^objects/sha256/([0-9a-f]{2})/([0-9a-f]{64})$`)
)

type PackageMetadata struct {
	Format                 string        `json:"format"`
	SourceID               string        `json:"sourceId"`
	ManifestDigest         string        `json:"manifestDigest"`
	ManifestEnvelopeSHA256 string        `json:"manifestEnvelopeSHA256"`
	RootVersion            *uint64       `json:"rootVersion,omitempty"`
	Files                  []PackageFile `json:"files"`
}

type PackageFile struct {
	Path   string `json:"path"`
	Length int64  `json:"length"`
	SHA256 string `json:"sha256"`
}

// BuildOptions freezes the signed release identity and the exact repository
// bytes included in one offline package. Files use paths relative to the
// source root; the archive adds the mandatory repository/ prefix.
type BuildOptions struct {
	Root                   string
	Output                 string
	SourceID               string
	ManifestDigest         string
	ManifestEnvelopeSHA256 string
	RootVersion            *uint64
	Files                  map[string][]byte
}

type packageLimits struct {
	maxCompressedBytes   int64
	maxUncompressedBytes int64
	maxArtifactBytes     int64
	maxManifestBytes     int64
	maxMembers           int
	maxPathBytes         int
}

type archiveEntry struct {
	name string
	body []byte
}

func defaultPackageLimits() packageLimits {
	return packageLimits{
		maxCompressedBytes: maxCompressedBytes, maxUncompressedBytes: maxUncompressedBytes,
		maxArtifactBytes: maxArtifactBytes, maxManifestBytes: maxManifestBytes,
		maxMembers: maxMembers, maxPathBytes: maxPathBytes,
	}
}

func BuildPackage(options BuildOptions) error {
	limits := defaultPackageLimits()
	if options.Root == "" || options.Output == "" {
		return fmt.Errorf("package root and output are required")
	}
	if filepath.Base(options.Output) != PackageFileName {
		return fmt.Errorf("package output filename must be %q", PackageFileName)
	}
	if _, err := os.Lstat(options.Output); err == nil {
		return fmt.Errorf("package output already exists")
	} else if !os.IsNotExist(err) {
		return err
	}
	metadata, err := metadataForOptions(options, limits)
	if err != nil {
		return err
	}
	if err := validateInputTree(options.Root, options.Files, limits); err != nil {
		return err
	}
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	entries := make([]archiveEntry, 0, len(options.Files)+1)
	entries = append(entries, archiveEntry{name: "package.json", body: metadataBytes})
	for _, name := range sortedNames(options.Files) {
		entries = append(entries, archiveEntry{name: "repository/" + name, body: options.Files[name]})
	}
	archive, err := canonicalArchive(entries)
	if err != nil {
		return err
	}
	if int64(len(archive)) > limits.maxUncompressedBytes {
		return fmt.Errorf("package uncompressed bytes exceed limit")
	}
	compressed, err := canonicalCompress(archive)
	if err != nil {
		return err
	}
	if int64(len(compressed)) > limits.maxCompressedBytes {
		return fmt.Errorf("package compressed bytes exceed limit")
	}
	if err := os.MkdirAll(filepath.Dir(options.Output), 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(options.Output), ".catalog-package-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := temporary.Write(compressed); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Chmod(temporaryPath, 0o644); err != nil {
		return err
	}
	if err := os.Link(temporaryPath, options.Output); err != nil {
		return fmt.Errorf("publish package without overwrite: %w", err)
	}
	verifyOptions := options
	verifyOptions.Root = ""
	verifyOptions.Output = ""
	if err := verifyPackage(options.Output, verifyOptions, limits); err != nil {
		_ = os.Remove(options.Output)
		return err
	}
	return nil
}

func VerifyPackage(packagePath string, expected BuildOptions) error {
	return verifyPackage(packagePath, expected, defaultPackageLimits())
}

func verifyPackage(packagePath string, expected BuildOptions, limits packageLimits) error {
	if packagePath == "" || filepath.Base(packagePath) != PackageFileName {
		return fmt.Errorf("package path must end in %q", PackageFileName)
	}
	expectedMetadata, err := metadataForOptions(expected, limits)
	if err != nil {
		return fmt.Errorf("expected package contract: %w", err)
	}
	info, err := os.Lstat(packagePath)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o644 {
		return fmt.Errorf("package must be a mode 0644 regular file")
	}
	if info.Size() <= 0 || info.Size() > limits.maxCompressedBytes {
		return fmt.Errorf("package compressed bytes exceed limit")
	}
	compressed, err := os.ReadFile(packagePath)
	if err != nil {
		return err
	}
	decoder, err := zstd.NewReader(bytes.NewReader(compressed),
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderMaxMemory(uint64(limits.maxUncompressedBytes)),
		zstd.WithDecoderMaxWindow(uint64(limits.maxUncompressedBytes)),
	)
	if err != nil {
		return fmt.Errorf("open zstd package: %w", err)
	}
	archive, readErr := io.ReadAll(io.LimitReader(decoder, limits.maxUncompressedBytes+1))
	decoder.Close()
	if readErr != nil {
		return fmt.Errorf("decompress package: %w", readErr)
	}
	if int64(len(archive)) > limits.maxUncompressedBytes {
		return fmt.Errorf("package uncompressed bytes exceed limit")
	}
	entries, err := parseArchive(archive, limits)
	if err != nil {
		return err
	}
	canonical, err := canonicalArchive(entries)
	if err != nil {
		return err
	}
	if !bytes.Equal(archive, canonical) {
		return fmt.Errorf("package tar bytes are not canonical USTAR")
	}
	recompressed, err := canonicalCompress(canonical)
	if err != nil {
		return err
	}
	if !bytes.Equal(compressed, recompressed) {
		return fmt.Errorf("package zstd bytes are not canonical or contain trailing data")
	}
	if len(entries) == 0 || entries[0].name != "package.json" {
		return fmt.Errorf("package.json must be the first package member")
	}
	metadata, err := parseMetadata(entries[0].body, limits)
	if err != nil {
		return err
	}
	if err := compareMetadata(metadata, expectedMetadata); err != nil {
		return err
	}
	if len(entries)-1 != len(metadata.Files) {
		return fmt.Errorf("package member count differs from package.json")
	}
	for index, file := range metadata.Files {
		entry := entries[index+1]
		if entry.name != file.Path || int64(len(entry.body)) != file.Length || digestBytes(entry.body) != file.SHA256 {
			return fmt.Errorf("package member %q differs from package.json", entry.name)
		}
		relative := strings.TrimPrefix(file.Path, "repository/")
		want, ok := expected.Files[relative]
		if !ok || !bytes.Equal(entry.body, want) {
			return fmt.Errorf("package member %q differs from expected bytes", entry.name)
		}
	}
	return nil
}

func metadataForOptions(options BuildOptions, limits packageLimits) (PackageMetadata, error) {
	if !sourceIDPattern.MatchString(options.SourceID) {
		return PackageMetadata{}, fmt.Errorf("invalid source ID")
	}
	if !digestPattern.MatchString(options.ManifestDigest) || !digestPattern.MatchString(options.ManifestEnvelopeSHA256) {
		return PackageMetadata{}, fmt.Errorf("invalid manifest digest")
	}
	if options.RootVersion != nil && *options.RootVersion == 0 {
		return PackageMetadata{}, fmt.Errorf("root version must be positive")
	}
	if len(options.Files) == 0 || len(options.Files)+1 > limits.maxMembers {
		return PackageMetadata{}, fmt.Errorf("invalid package member count")
	}
	metadata := PackageMetadata{
		Format: PackageFormat, SourceID: options.SourceID, ManifestDigest: options.ManifestDigest,
		ManifestEnvelopeSHA256: options.ManifestEnvelopeSHA256, RootVersion: cloneUint64(options.RootVersion),
		Files: make([]PackageFile, 0, len(options.Files)),
	}
	seenCase := make(map[string]struct{}, len(options.Files))
	for _, relative := range sortedNames(options.Files) {
		content := options.Files[relative]
		member := "repository/" + relative
		if err := validateRepositoryMemberPath(member, limits); err != nil {
			return PackageMetadata{}, err
		}
		folded := strings.ToLower(member)
		if _, duplicate := seenCase[folded]; duplicate {
			return PackageMetadata{}, fmt.Errorf("case-colliding package path %q", member)
		}
		seenCase[folded] = struct{}{}
		memberLimit := limits.maxArtifactBytes
		if relative == "manifest.json" || relative == "root.json" {
			memberLimit = limits.maxManifestBytes
		}
		if len(content) == 0 || int64(len(content)) > memberLimit {
			return PackageMetadata{}, fmt.Errorf("package member %q has invalid length", member)
		}
		contentDigest := digestBytes(content)
		if match := objectPathPattern.FindStringSubmatch(relative); match != nil && match[2] != contentDigest {
			return PackageMetadata{}, fmt.Errorf("package object path digest differs for %q", member)
		}
		metadata.Files = append(metadata.Files, PackageFile{Path: member, Length: int64(len(content)), SHA256: contentDigest})
	}
	manifest, ok := options.Files["manifest.json"]
	if !ok {
		return PackageMetadata{}, fmt.Errorf("package requires repository/manifest.json")
	}
	if digestBytes(manifest) != options.ManifestEnvelopeSHA256 {
		return PackageMetadata{}, fmt.Errorf("manifest envelope digest differs")
	}
	if _, hasRoot := options.Files["root.json"]; !hasRoot && options.RootVersion != nil {
		return PackageMetadata{}, fmt.Errorf("root version requires repository/root.json")
	}
	if err := validateMetadata(metadata, limits); err != nil {
		return PackageMetadata{}, err
	}
	return metadata, nil
}

func validateInputTree(root string, expected map[string][]byte, limits packageLimits) error {
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("package root must be a real directory")
	}
	found := make(map[string]struct{}, len(expected))
	err = filepath.WalkDir(root, func(itemPath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if itemPath == root {
			return nil
		}
		entryInfo, err := entry.Info()
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, itemPath)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(relative)
		if entryInfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("package path %q is a symlink", name)
		}
		if entry.IsDir() {
			if entryInfo.Mode().Perm() != 0o755 {
				return fmt.Errorf("package directory %q must use mode 0755", name)
			}
			return nil
		}
		want, ok := expected[name]
		if !ok {
			return fmt.Errorf("package tree contains extra file %q", name)
		}
		if !entryInfo.Mode().IsRegular() || entryInfo.Mode().Perm() != 0o644 {
			return fmt.Errorf("package file %q must be a mode 0644 regular file", name)
		}
		content, err := os.ReadFile(itemPath)
		if err != nil {
			return err
		}
		if !bytes.Equal(content, want) {
			return fmt.Errorf("package tree file %q differs from expected bytes", name)
		}
		found[name] = struct{}{}
		return nil
	})
	if err != nil {
		return err
	}
	if len(found) != len(expected) {
		return fmt.Errorf("package tree is missing expected files")
	}
	return nil
}

func parseArchive(content []byte, limits packageLimits) ([]archiveEntry, error) {
	reader := tar.NewReader(bytes.NewReader(content))
	entries := make([]archiveEntry, 0)
	seen := make(map[string]struct{})
	seenCase := make(map[string]struct{})
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read package tar: %w", err)
		}
		if len(entries) >= limits.maxMembers {
			return nil, fmt.Errorf("package member count exceeds limit")
		}
		if err := validateArchiveHeader(header, limits); err != nil {
			return nil, err
		}
		if _, duplicate := seen[header.Name]; duplicate {
			return nil, fmt.Errorf("package contains duplicate member %q", header.Name)
		}
		folded := strings.ToLower(header.Name)
		if _, collision := seenCase[folded]; collision {
			return nil, fmt.Errorf("package contains case-colliding member %q", header.Name)
		}
		seen[header.Name] = struct{}{}
		seenCase[folded] = struct{}{}
		memberLimit := limits.maxArtifactBytes
		if header.Name == "package.json" || header.Name == "repository/manifest.json" || header.Name == "repository/root.json" {
			memberLimit = limits.maxManifestBytes
		}
		if header.Size <= 0 || header.Size > memberLimit {
			return nil, fmt.Errorf("package member %q has invalid length", header.Name)
		}
		body, err := io.ReadAll(io.LimitReader(reader, memberLimit+1))
		if err != nil {
			return nil, err
		}
		if int64(len(body)) != header.Size {
			return nil, fmt.Errorf("package member %q length differs", header.Name)
		}
		entries = append(entries, archiveEntry{name: header.Name, body: body})
	}
	return entries, nil
}

func validateArchiveHeader(header *tar.Header, limits packageLimits) error {
	if header.Format != tar.FormatUSTAR || header.Typeflag != tar.TypeReg || header.Mode != 0o644 ||
		header.Uid != 0 || header.Gid != 0 || !header.ModTime.Equal(canonicalTime) ||
		!header.AccessTime.IsZero() || !header.ChangeTime.IsZero() || header.Uname != "" || header.Gname != "" ||
		header.Linkname != "" || header.Devmajor != 0 || header.Devminor != 0 || len(header.PAXRecords) != 0 || len(header.Xattrs) != 0 {
		return fmt.Errorf("package member %q has non-canonical USTAR metadata", header.Name)
	}
	if header.Name == "package.json" {
		if len(header.Name) > limits.maxPathBytes {
			return fmt.Errorf("package path exceeds limit")
		}
		return nil
	}
	return validateRepositoryMemberPath(header.Name, limits)
}

func validateRepositoryMemberPath(name string, limits packageLimits) error {
	if len(name) == 0 || len(name) > limits.maxPathBytes || strings.Contains(name, "\\") ||
		path.IsAbs(name) || path.Clean(name) != name || name == "." || strings.HasPrefix(name, "../") ||
		!strings.HasPrefix(name, "repository/") {
		return fmt.Errorf("unsafe package path %q", name)
	}
	relative := strings.TrimPrefix(name, "repository/")
	if relative == "manifest.json" || relative == "root.json" {
		return nil
	}
	match := objectPathPattern.FindStringSubmatch(relative)
	if match == nil || match[1] != match[2][:2] {
		return fmt.Errorf("package path %q is outside the repository allowlist", name)
	}
	return nil
}

func parseMetadata(content []byte, limits packageLimits) (PackageMetadata, error) {
	if err := rejectDuplicateJSONFields(content); err != nil {
		return PackageMetadata{}, fmt.Errorf("decode package.json: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var metadata PackageMetadata
	if err := decoder.Decode(&metadata); err != nil {
		return PackageMetadata{}, fmt.Errorf("decode package.json: %w", err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return PackageMetadata{}, fmt.Errorf("package.json has trailing JSON data")
	}
	canonical, err := json.Marshal(metadata)
	if err != nil {
		return PackageMetadata{}, err
	}
	if !bytes.Equal(content, canonical) {
		return PackageMetadata{}, fmt.Errorf("package.json is not canonical JSON")
	}
	if err := validateMetadata(metadata, limits); err != nil {
		return PackageMetadata{}, err
	}
	return metadata, nil
}

func validateMetadata(metadata PackageMetadata, limits packageLimits) error {
	if metadata.Format != PackageFormat || !sourceIDPattern.MatchString(metadata.SourceID) ||
		!digestPattern.MatchString(metadata.ManifestDigest) || !digestPattern.MatchString(metadata.ManifestEnvelopeSHA256) {
		return fmt.Errorf("package.json identity fields are invalid")
	}
	if metadata.RootVersion != nil && *metadata.RootVersion == 0 {
		return fmt.Errorf("package.json root version is invalid")
	}
	if len(metadata.Files) == 0 || len(metadata.Files)+1 > limits.maxMembers {
		return fmt.Errorf("package.json file count is invalid")
	}
	seen := make(map[string]struct{}, len(metadata.Files))
	seenCase := make(map[string]struct{}, len(metadata.Files))
	manifestCount := 0
	rootCount := 0
	prior := ""
	for _, file := range metadata.Files {
		if err := validateRepositoryMemberPath(file.Path, limits); err != nil {
			return err
		}
		if prior != "" && file.Path <= prior {
			return fmt.Errorf("package.json file table is not strictly byte-sorted")
		}
		prior = file.Path
		if _, duplicate := seen[file.Path]; duplicate {
			return fmt.Errorf("package.json repeats file %q", file.Path)
		}
		folded := strings.ToLower(file.Path)
		if _, collision := seenCase[folded]; collision {
			return fmt.Errorf("package.json contains case-colliding path %q", file.Path)
		}
		seen[file.Path] = struct{}{}
		seenCase[folded] = struct{}{}
		if file.Length <= 0 || !digestPattern.MatchString(file.SHA256) {
			return fmt.Errorf("package.json file %q has invalid integrity metadata", file.Path)
		}
		if match := objectPathPattern.FindStringSubmatch(strings.TrimPrefix(file.Path, "repository/")); match != nil && match[2] != file.SHA256 {
			return fmt.Errorf("package.json object path digest differs for %q", file.Path)
		}
		if file.Path == "repository/manifest.json" {
			manifestCount++
			if file.SHA256 != metadata.ManifestEnvelopeSHA256 {
				return fmt.Errorf("manifest envelope digest differs from file table")
			}
		}
		if file.Path == "repository/root.json" {
			rootCount++
		}
	}
	if manifestCount != 1 || rootCount > 1 || (metadata.RootVersion != nil && rootCount != 1) {
		return fmt.Errorf("package.json repository metadata members are incomplete")
	}
	return nil
}

func compareMetadata(got, want PackageMetadata) error {
	if got.Format != want.Format || got.SourceID != want.SourceID || got.ManifestDigest != want.ManifestDigest ||
		got.ManifestEnvelopeSHA256 != want.ManifestEnvelopeSHA256 || !equalUint64(got.RootVersion, want.RootVersion) ||
		len(got.Files) != len(want.Files) {
		return fmt.Errorf("package.json differs from expected release identity")
	}
	for index := range got.Files {
		if got.Files[index] != want.Files[index] {
			return fmt.Errorf("package.json file table differs from expected bytes")
		}
	}
	return nil
}

func canonicalArchive(entries []archiveEntry) ([]byte, error) {
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, entry := range entries {
		header := &tar.Header{
			Name: entry.name, Mode: 0o644, Uid: 0, Gid: 0, Size: int64(len(entry.body)),
			ModTime: canonicalTime, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR,
		}
		if err := writer.WriteHeader(header); err != nil {
			writer.Close()
			return nil, err
		}
		if _, err := writer.Write(entry.body); err != nil {
			writer.Close()
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func canonicalCompress(content []byte) ([]byte, error) {
	var buffer bytes.Buffer
	encoder, err := zstd.NewWriter(&buffer,
		zstd.WithEncoderConcurrency(1),
		zstd.WithEncoderLevel(zstd.SpeedDefault),
		zstd.WithEncoderCRC(true),
	)
	if err != nil {
		return nil, err
	}
	if _, err := encoder.Write(content); err != nil {
		encoder.Close()
		return nil, err
	}
	if err := encoder.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func rejectDuplicateJSONFields(content []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil {
		return err
	}
	if err := walkJSONValue(decoder, first); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

func walkJSONValue(decoder *json.Decoder, token json.Token) error {
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			seen[key] = struct{}{}
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := walkJSONValue(decoder, value); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return fmt.Errorf("invalid JSON object")
		}
	case '[':
		for decoder.More() {
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := walkJSONValue(decoder, value); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return fmt.Errorf("invalid JSON array")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter")
	}
	return nil
}

func sortedNames(files map[string][]byte) []string {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func digestBytes(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func cloneUint64(value *uint64) *uint64 {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func equalUint64(left, right *uint64) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
