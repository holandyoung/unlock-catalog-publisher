// Package repository materializes assembled Catalog releases into the
// protected Git release tree.
package repository

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	ReleasePrefix       = "catalog/sources"
	MaxReleaseFileBytes = 256 << 20
)

var (
	sourceIDPattern       = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	digestPattern         = `[0-9a-f]{64}`
	versionPattern        = `[0-9]{20}`
	objectPathPattern     = regexp.MustCompile(`^objects/sha256/([0-9a-f]{2})/(` + digestPattern + `)$`)
	archivePathPattern    = regexp.MustCompile(`^archive/` + versionPattern + `/` + digestPattern + `/manifest\.json$`)
	rootPathPattern       = regexp.MustCompile(`^roots/` + versionPattern + `/` + digestPattern + `/root\.json$`)
	packagePathPattern    = regexp.MustCompile(`^packages/` + versionPattern + `/` + digestPattern + `/unlock-catalog-package-v1\.tar\.zst$`)
	ErrImmutableChanged   = errors.New("immutable release path changed")
	ErrInvalidReleaseTree = errors.New("invalid release tree")
)

type File struct {
	Path string
	Body []byte
}

type Release struct {
	SourceID string
	Files    []File
}

type MaterializeReport struct {
	SourceID  string `json:"sourceId"`
	FileCount int    `json:"fileCount"`
	FileBytes int64  `json:"fileBytes"`
}

type fileKind uint8

const (
	kindLiveManifest fileKind = iota + 1
	kindLiveRoot
	kindObject
	kindManifestArchive
	kindRootArchive
	kindPackage
)

type treeFile struct {
	body []byte
	mode fs.FileMode
	kind fileKind
}

func MaterializeRelease(repositoryRoot string, release Release) (MaterializeReport, error) {
	if err := validateRepositoryRoot(repositoryRoot); err != nil {
		return MaterializeReport{}, err
	}
	incoming, err := validateRelease(release)
	if err != nil {
		return MaterializeReport{}, err
	}
	sourceRoot := filepath.Join(repositoryRoot, filepath.FromSlash(ReleasePrefix), release.SourceID)
	existing, exists, err := readSourceTree(sourceRoot, release.SourceID)
	if err != nil {
		return MaterializeReport{}, err
	}
	merged := cloneTree(existing)
	for relative, file := range incoming {
		if prior, ok := merged[relative]; ok && immutable(file.kind) && !bytes.Equal(prior.body, file.body) {
			return MaterializeReport{}, fmt.Errorf("%w: %s", ErrImmutableChanged, relative)
		}
		merged[relative] = file
	}
	if err := validateCompleteSourceTree(release.SourceID, merged); err != nil {
		return MaterializeReport{}, err
	}

	prefixRoot := filepath.Dir(sourceRoot)
	if err := os.MkdirAll(prefixRoot, 0o755); err != nil {
		return MaterializeReport{}, fmt.Errorf("create release prefix: %w", err)
	}
	staging, err := os.MkdirTemp(prefixRoot, ".materialize-"+release.SourceID+"-")
	if err != nil {
		return MaterializeReport{}, fmt.Errorf("create release staging: %w", err)
	}
	defer os.RemoveAll(staging)
	if err := os.Chmod(staging, 0o755); err != nil {
		return MaterializeReport{}, err
	}
	if err := writeSourceTree(staging, merged); err != nil {
		return MaterializeReport{}, err
	}
	if !exists {
		if err := os.Rename(staging, sourceRoot); err != nil {
			return MaterializeReport{}, fmt.Errorf("install release tree: %w", err)
		}
	} else if err := replaceSourceTree(sourceRoot, staging); err != nil {
		return MaterializeReport{}, err
	}

	var total int64
	for _, file := range release.Files {
		total += int64(len(file.Body))
	}
	return MaterializeReport{SourceID: release.SourceID, FileCount: len(release.Files), FileBytes: total}, nil
}

func VerifyReleaseDiff(baseRoot, candidateRoot string) error {
	if err := validateRepositoryRoot(baseRoot); err != nil {
		return fmt.Errorf("base repository: %w", err)
	}
	if err := validateRepositoryRoot(candidateRoot); err != nil {
		return fmt.Errorf("candidate repository: %w", err)
	}
	base, err := readRepositorySources(baseRoot)
	if err != nil {
		return fmt.Errorf("base repository: %w", err)
	}
	candidate, err := readRepositorySources(candidateRoot)
	if err != nil {
		return fmt.Errorf("candidate repository: %w", err)
	}
	for sourceID, baseFiles := range base {
		candidateFiles, ok := candidate[sourceID]
		if !ok {
			return fmt.Errorf("%w: source %q was deleted", ErrImmutableChanged, sourceID)
		}
		for relative, baseFile := range baseFiles {
			if !immutable(baseFile.kind) {
				continue
			}
			candidateFile, ok := candidateFiles[relative]
			if !ok || candidateFile.mode != baseFile.mode || !bytes.Equal(candidateFile.body, baseFile.body) {
				return fmt.Errorf("%w: %s/%s", ErrImmutableChanged, sourceID, relative)
			}
		}
	}
	return nil
}

func ValidateReleaseChangePaths(changed []string) (bool, error) {
	releaseChanged := false
	nonRelease := make([]string, 0)
	for _, changedPath := range changed {
		if changedPath == "" || path.IsAbs(changedPath) || path.Clean(changedPath) != changedPath || strings.Contains(changedPath, "\\") {
			return false, fmt.Errorf("unsafe changed path %q", changedPath)
		}
		prefix := ReleasePrefix + "/"
		if !strings.HasPrefix(changedPath, prefix) {
			nonRelease = append(nonRelease, changedPath)
			continue
		}
		remainder := strings.TrimPrefix(changedPath, prefix)
		separator := strings.IndexByte(remainder, '/')
		if separator < 1 {
			nonRelease = append(nonRelease, changedPath)
			continue
		}
		sourceID, relative := remainder[:separator], remainder[separator+1:]
		if !sourceIDPattern.MatchString(sourceID) || !validReleasePathShape(relative) {
			return false, fmt.Errorf("%w: changed path %q is not a release path", ErrInvalidReleaseTree, changedPath)
		}
		releaseChanged = true
	}
	if releaseChanged && len(nonRelease) != 0 {
		sort.Strings(nonRelease)
		return false, fmt.Errorf("release change includes non-release path %q", nonRelease[0])
	}
	return releaseChanged, nil
}

func validateRepositoryRoot(root string) error {
	if root == "" {
		return fmt.Errorf("repository root is required")
	}
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("repository root must be a real directory")
	}
	return nil
}

func validateRelease(release Release) (map[string]treeFile, error) {
	if !sourceIDPattern.MatchString(release.SourceID) {
		return nil, fmt.Errorf("%w: invalid source ID", ErrInvalidReleaseTree)
	}
	if len(release.Files) == 0 {
		return nil, fmt.Errorf("%w: release has no files", ErrInvalidReleaseTree)
	}
	prefix := path.Join(ReleasePrefix, release.SourceID) + "/"
	files := make(map[string]treeFile, len(release.Files))
	for _, file := range release.Files {
		if file.Path == "" || path.IsAbs(file.Path) || path.Clean(file.Path) != file.Path ||
			strings.Contains(file.Path, "\\") || !strings.HasPrefix(file.Path, prefix) {
			return nil, fmt.Errorf("%w: unsafe release path %q", ErrInvalidReleaseTree, file.Path)
		}
		relative := strings.TrimPrefix(file.Path, prefix)
		kind, err := classifyReleasePath(relative, file.Body)
		if err != nil {
			return nil, err
		}
		if len(file.Body) == 0 || len(file.Body) > MaxReleaseFileBytes {
			return nil, fmt.Errorf("%w: invalid size for %q", ErrInvalidReleaseTree, file.Path)
		}
		if _, duplicate := files[relative]; duplicate {
			return nil, fmt.Errorf("%w: duplicate path %q", ErrInvalidReleaseTree, file.Path)
		}
		files[relative] = treeFile{body: append([]byte(nil), file.Body...), mode: 0o644, kind: kind}
	}
	if err := validateCompleteSourceTree(release.SourceID, files); err != nil {
		return nil, err
	}
	return files, nil
}

func classifyReleasePath(relative string, body []byte) (fileKind, error) {
	switch relative {
	case "manifest.json":
		return kindLiveManifest, nil
	case "root.json":
		return kindLiveRoot, nil
	}
	if match := objectPathPattern.FindStringSubmatch(relative); match != nil {
		digest := digestBytes(body)
		if match[1] != digest[:2] || match[2] != digest {
			return 0, fmt.Errorf("%w: object path digest differs", ErrInvalidReleaseTree)
		}
		return kindObject, nil
	}
	if archivePathPattern.MatchString(relative) {
		return kindManifestArchive, nil
	}
	if rootPathPattern.MatchString(relative) {
		return kindRootArchive, nil
	}
	if packagePathPattern.MatchString(relative) {
		return kindPackage, nil
	}
	return 0, fmt.Errorf("%w: unknown release path %q", ErrInvalidReleaseTree, relative)
}

func validReleasePathShape(relative string) bool {
	if relative == "manifest.json" || relative == "root.json" {
		return true
	}
	return objectPathPattern.MatchString(relative) || archivePathPattern.MatchString(relative) ||
		rootPathPattern.MatchString(relative) || packagePathPattern.MatchString(relative)
}

func validateCompleteSourceTree(sourceID string, files map[string]treeFile) error {
	manifest, manifestOK := files["manifest.json"]
	root, rootOK := files["root.json"]
	if !manifestOK || !rootOK {
		return fmt.Errorf("%w: source %q requires live manifest and root", ErrInvalidReleaseTree, sourceID)
	}
	var objectCount, manifestArchiveCount, rootArchiveCount, packageCount int
	var manifestArchived, rootArchived bool
	for _, file := range files {
		switch file.kind {
		case kindObject:
			objectCount++
		case kindManifestArchive:
			manifestArchiveCount++
			manifestArchived = manifestArchived || bytes.Equal(file.body, manifest.body)
		case kindRootArchive:
			rootArchiveCount++
			rootArchived = rootArchived || bytes.Equal(file.body, root.body)
		case kindPackage:
			packageCount++
		}
	}
	if objectCount == 0 || manifestArchiveCount == 0 || rootArchiveCount == 0 || packageCount == 0 ||
		!manifestArchived || !rootArchived {
		return fmt.Errorf("%w: source %q is incomplete or live bytes lack an immutable archive", ErrInvalidReleaseTree, sourceID)
	}
	return nil
}

func readRepositorySources(repositoryRoot string) (map[string]map[string]treeFile, error) {
	prefixRoot := filepath.Join(repositoryRoot, filepath.FromSlash(ReleasePrefix))
	entries, err := os.ReadDir(prefixRoot)
	if os.IsNotExist(err) {
		return map[string]map[string]treeFile{}, nil
	}
	if err != nil {
		return nil, err
	}
	result := make(map[string]map[string]treeFile)
	for _, entry := range entries {
		if entry.Name() == "README.md" && entry.Type().IsRegular() {
			continue
		}
		if !entry.IsDir() || !sourceIDPattern.MatchString(entry.Name()) {
			return nil, fmt.Errorf("%w: unexpected release-prefix entry %q", ErrInvalidReleaseTree, entry.Name())
		}
		files, _, err := readSourceTree(filepath.Join(prefixRoot, entry.Name()), entry.Name())
		if err != nil {
			return nil, err
		}
		if err := validateCompleteSourceTree(entry.Name(), files); err != nil {
			return nil, err
		}
		result[entry.Name()] = files
	}
	return result, nil
}

func readSourceTree(sourceRoot, sourceID string) (map[string]treeFile, bool, error) {
	info, err := os.Lstat(sourceRoot)
	if os.IsNotExist(err) {
		return map[string]treeFile{}, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o755 {
		return nil, false, fmt.Errorf("%w: source %q is not a mode 0755 directory", ErrInvalidReleaseTree, sourceID)
	}
	files := map[string]treeFile{}
	err = filepath.WalkDir(sourceRoot, func(filePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if filePath == sourceRoot {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if info.Mode().Perm() != 0o755 {
				return fmt.Errorf("%w: directory mode differs", ErrInvalidReleaseTree)
			}
			return nil
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o644 {
			return fmt.Errorf("%w: unsafe file metadata", ErrInvalidReleaseTree)
		}
		relative, err := filepath.Rel(sourceRoot, filePath)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		body, err := os.ReadFile(filePath)
		if err != nil {
			return err
		}
		kind, err := classifyReleasePath(relative, body)
		if err != nil {
			return err
		}
		files[relative] = treeFile{body: body, mode: info.Mode().Perm(), kind: kind}
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return files, true, nil
}

func writeSourceTree(root string, files map[string]treeFile) error {
	paths := make([]string, 0, len(files))
	for relative := range files {
		paths = append(paths, relative)
	}
	sort.Strings(paths)
	for _, relative := range paths {
		filePath := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filePath, files[relative].body, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func replaceSourceTree(sourceRoot, staging string) error {
	backup, err := os.MkdirTemp(filepath.Dir(sourceRoot), ".previous-"+filepath.Base(sourceRoot)+"-")
	if err != nil {
		return err
	}
	if err := os.Remove(backup); err != nil {
		return err
	}
	if err := os.Rename(sourceRoot, backup); err != nil {
		return fmt.Errorf("stage prior release tree: %w", err)
	}
	if err := os.Rename(staging, sourceRoot); err != nil {
		_ = os.Rename(backup, sourceRoot)
		return fmt.Errorf("install release tree: %w", err)
	}
	if err := os.RemoveAll(backup); err != nil {
		return fmt.Errorf("remove prior release staging: %w", err)
	}
	return nil
}

func cloneTree(source map[string]treeFile) map[string]treeFile {
	result := make(map[string]treeFile, len(source))
	for relative, file := range source {
		file.body = append([]byte(nil), file.body...)
		result[relative] = file
	}
	return result
}

func immutable(kind fileKind) bool {
	return kind != kindLiveManifest && kind != kindLiveRoot
}

func digestBytes(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}
