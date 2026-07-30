package repository

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var ErrMirrorMismatch = errors.New("public mirror differs from protected release tree")

type MirrorReport struct {
	SourceCount int   `json:"sourceCount"`
	FileCount   int   `json:"fileCount"`
	FileBytes   int64 `json:"fileBytes"`
}

// ReplicatePublicMirror copies the protected release tree without rebuilding or
// resigning any release content. The mirror root is another repository-shaped
// directory whose Catalog sources are replaced atomically after validation.
func ReplicatePublicMirror(sourceRepositoryRoot, mirrorRepositoryRoot string) (MirrorReport, error) {
	if err := validateMirrorRoots(sourceRepositoryRoot, mirrorRepositoryRoot); err != nil {
		return MirrorReport{}, err
	}
	sources, err := readRepositorySources(sourceRepositoryRoot)
	if err != nil {
		return MirrorReport{}, fmt.Errorf("read protected release tree: %w", err)
	}
	existing, err := readRepositorySources(mirrorRepositoryRoot)
	if err != nil {
		return MirrorReport{}, fmt.Errorf("read public mirror: %w", err)
	}
	if err := ensureMirrorImmutablesUnchanged(sources, existing); err != nil {
		return MirrorReport{}, err
	}

	stagingRoot, err := os.MkdirTemp(mirrorRepositoryRoot, ".public-mirror-")
	if err != nil {
		return MirrorReport{}, fmt.Errorf("create public mirror staging root: %w", err)
	}
	defer os.RemoveAll(stagingRoot)
	if err := os.Chmod(stagingRoot, 0o755); err != nil {
		return MirrorReport{}, fmt.Errorf("set public mirror staging mode: %w", err)
	}
	stagingPrefix := filepath.Join(stagingRoot, filepath.FromSlash(ReleasePrefix))
	if err := writeMirrorSources(stagingPrefix, sources); err != nil {
		return MirrorReport{}, fmt.Errorf("stage public mirror: %w", err)
	}
	if err := VerifyPublicMirror(sourceRepositoryRoot, stagingRoot); err != nil {
		return MirrorReport{}, fmt.Errorf("verify staged public mirror: %w", err)
	}

	mirrorPrefix := filepath.Join(mirrorRepositoryRoot, filepath.FromSlash(ReleasePrefix))
	if err := installMirrorPrefix(mirrorPrefix, stagingPrefix, func() error {
		return VerifyPublicMirror(sourceRepositoryRoot, mirrorRepositoryRoot)
	}); err != nil {
		return MirrorReport{}, err
	}
	return mirrorReport(sources), nil
}

// VerifyPublicMirror compares every signed release byte and file mode. It does
// not fetch, resign, or interpret provider-specific mirror configuration.
func VerifyPublicMirror(sourceRepositoryRoot, mirrorRepositoryRoot string) error {
	if err := validateMirrorRoots(sourceRepositoryRoot, mirrorRepositoryRoot); err != nil {
		return err
	}
	sources, err := readRepositorySources(sourceRepositoryRoot)
	if err != nil {
		return fmt.Errorf("read protected release tree: %w", err)
	}
	mirror, err := readRepositorySources(mirrorRepositoryRoot)
	if err != nil {
		return fmt.Errorf("%w: read mirror: %v", ErrMirrorMismatch, err)
	}
	if err := compareMirrorTrees(sources, mirror); err != nil {
		return err
	}
	return nil
}

func validateMirrorRoots(sourceRepositoryRoot, mirrorRepositoryRoot string) error {
	if err := validateRepositoryRoot(sourceRepositoryRoot); err != nil {
		return fmt.Errorf("protected repository root: %w", err)
	}
	if err := validateRepositoryRoot(mirrorRepositoryRoot); err != nil {
		return fmt.Errorf("mirror repository root: %w", err)
	}
	source, err := filepath.EvalSymlinks(sourceRepositoryRoot)
	if err != nil {
		return fmt.Errorf("resolve protected repository root: %w", err)
	}
	mirror, err := filepath.EvalSymlinks(mirrorRepositoryRoot)
	if err != nil {
		return fmt.Errorf("resolve mirror repository root: %w", err)
	}
	source, err = filepath.Abs(source)
	if err != nil {
		return err
	}
	mirror, err = filepath.Abs(mirror)
	if err != nil {
		return err
	}
	if source == mirror || pathContains(source, mirror) || pathContains(mirror, source) {
		return fmt.Errorf("protected and mirror repository roots must be separate")
	}
	return nil
}

func pathContains(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func ensureMirrorImmutablesUnchanged(sources, mirror map[string]map[string]treeFile) error {
	for sourceID, mirrorFiles := range mirror {
		sourceFiles, ok := sources[sourceID]
		if !ok {
			return fmt.Errorf("%w: mirror contains removed source %q", ErrImmutableChanged, sourceID)
		}
		for relative, mirrorFile := range mirrorFiles {
			if !immutable(mirrorFile.kind) {
				continue
			}
			sourceFile, ok := sourceFiles[relative]
			if !ok || sourceFile.mode != mirrorFile.mode || !bytes.Equal(sourceFile.body, mirrorFile.body) {
				return fmt.Errorf("%w: %s/%s", ErrImmutableChanged, sourceID, relative)
			}
		}
	}
	return nil
}

func writeMirrorSources(prefixRoot string, sources map[string]map[string]treeFile) error {
	if err := os.MkdirAll(prefixRoot, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(prefixRoot, 0o755); err != nil {
		return err
	}
	sourceIDs := make([]string, 0, len(sources))
	for sourceID := range sources {
		sourceIDs = append(sourceIDs, sourceID)
	}
	sort.Strings(sourceIDs)
	for _, sourceID := range sourceIDs {
		sourceRoot := filepath.Join(prefixRoot, sourceID)
		if err := os.Mkdir(sourceRoot, 0o755); err != nil {
			return err
		}
		if err := os.Chmod(sourceRoot, 0o755); err != nil {
			return err
		}
		if err := writeSourceTree(sourceRoot, sources[sourceID]); err != nil {
			return err
		}
		if err := setMirrorTreeModes(sourceRoot, sources[sourceID]); err != nil {
			return err
		}
	}
	return nil
}

func setMirrorTreeModes(sourceRoot string, files map[string]treeFile) error {
	return filepath.Walk(sourceRoot, func(filePath string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			return os.Chmod(filePath, 0o755)
		}
		relative, err := filepath.Rel(sourceRoot, filePath)
		if err != nil {
			return err
		}
		file, ok := files[filepath.ToSlash(relative)]
		if !ok {
			return fmt.Errorf("unexpected staged mirror path %q", relative)
		}
		return os.Chmod(filePath, file.mode)
	})
}

func installMirrorPrefix(mirrorPrefix, stagingPrefix string, verify func() error) error {
	if err := os.MkdirAll(filepath.Dir(mirrorPrefix), 0o755); err != nil {
		return fmt.Errorf("create public mirror prefix parent: %w", err)
	}
	_, statErr := os.Lstat(mirrorPrefix)
	exists := statErr == nil
	if statErr != nil && !os.IsNotExist(statErr) {
		return fmt.Errorf("inspect public mirror prefix: %w", statErr)
	}

	backup := ""
	if exists {
		var err error
		backup, err = os.MkdirTemp(filepath.Dir(mirrorPrefix), ".previous-mirror-")
		if err != nil {
			return fmt.Errorf("create public mirror backup path: %w", err)
		}
		if err := os.Remove(backup); err != nil {
			return err
		}
		if err := os.Rename(mirrorPrefix, backup); err != nil {
			return fmt.Errorf("stage prior public mirror: %w", err)
		}
	}
	if err := os.Rename(stagingPrefix, mirrorPrefix); err != nil {
		if exists {
			_ = os.Rename(backup, mirrorPrefix)
		}
		return fmt.Errorf("install public mirror: %w", err)
	}
	if err := verify(); err != nil {
		rollbackErr := os.RemoveAll(mirrorPrefix)
		if exists && rollbackErr == nil {
			rollbackErr = os.Rename(backup, mirrorPrefix)
		}
		if rollbackErr != nil {
			return fmt.Errorf("readback failed: %w; rollback failed: %v", err, rollbackErr)
		}
		return fmt.Errorf("readback failed and prior mirror was restored: %w", err)
	}
	if exists {
		if err := os.RemoveAll(backup); err != nil {
			return fmt.Errorf("remove prior public mirror staging: %w", err)
		}
	}
	return nil
}

func compareMirrorTrees(sources, mirror map[string]map[string]treeFile) error {
	if len(sources) != len(mirror) {
		return fmt.Errorf("%w: source count differs", ErrMirrorMismatch)
	}
	for sourceID, sourceFiles := range sources {
		mirrorFiles, ok := mirror[sourceID]
		if !ok || len(sourceFiles) != len(mirrorFiles) {
			return fmt.Errorf("%w: source %q file set differs", ErrMirrorMismatch, sourceID)
		}
		for relative, sourceFile := range sourceFiles {
			mirrorFile, ok := mirrorFiles[relative]
			if !ok || sourceFile.mode != mirrorFile.mode || !bytes.Equal(sourceFile.body, mirrorFile.body) {
				return fmt.Errorf("%w: %s/%s", ErrMirrorMismatch, sourceID, relative)
			}
		}
	}
	return nil
}

func mirrorReport(sources map[string]map[string]treeFile) MirrorReport {
	report := MirrorReport{SourceCount: len(sources)}
	for _, files := range sources {
		report.FileCount += len(files)
		for _, file := range files {
			report.FileBytes += int64(len(file.body))
		}
	}
	return report
}
