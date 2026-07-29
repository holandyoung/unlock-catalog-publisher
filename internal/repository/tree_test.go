package repository

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMaterializeReleasePreservesImmutableHistoryAndUpdatesLiveTogether(t *testing.T) {
	repositoryRoot := t.TempDir()
	oldRelease := testRelease("catalog-test-data", "old manifest", "old root", "old object")
	if _, err := MaterializeRelease(repositoryRoot, oldRelease); err != nil {
		t.Fatalf("materialize old release: %v", err)
	}
	oldImmutable := readTreeFile(t, repositoryRoot, oldRelease.Files[2].Path)

	newRelease := testRelease("catalog-test-data", "new manifest", "new root", "new object")
	report, err := MaterializeRelease(repositoryRoot, newRelease)
	if err != nil {
		t.Fatalf("materialize new release: %v", err)
	}
	if report.SourceID != newRelease.SourceID || report.FileCount != len(newRelease.Files) || report.FileBytes == 0 {
		t.Fatalf("materialize report = %+v", report)
	}
	if got := readTreeFile(t, repositoryRoot, oldRelease.Files[2].Path); !bytes.Equal(got, oldImmutable) {
		t.Fatal("new release changed prior immutable bytes")
	}
	if got := readTreeFile(t, repositoryRoot, sourcePath(newRelease.SourceID, "manifest.json")); string(got) != "new manifest" {
		t.Fatalf("live manifest = %q", got)
	}
	if err := VerifyReleaseDiff(repositoryRoot, repositoryRoot); err != nil {
		t.Fatalf("verify materialized tree: %v", err)
	}
}

func TestMaterializeReleaseValidationFailureLeavesRepositoryUnchanged(t *testing.T) {
	repositoryRoot := t.TempDir()
	valid := testRelease("catalog-test-data", "manifest", "root", "object")
	if _, err := MaterializeRelease(repositoryRoot, valid); err != nil {
		t.Fatal(err)
	}
	before := snapshotTree(t, repositoryRoot)

	tests := map[string]func(Release) Release{
		"immutable collision": func(release Release) Release {
			release.Files[2].Body = []byte("different bytes under the same immutable path")
			return release
		},
		"traversal": func(release Release) Release {
			release.Files = append(release.Files, File{Path: "../outside", Body: []byte("x")})
			return release
		},
		"duplicate": func(release Release) Release {
			release.Files = append(release.Files, release.Files[0])
			return release
		},
		"extra file": func(release Release) Release {
			release.Files = append(release.Files, File{Path: sourcePath(release.SourceID, "notes.txt"), Body: []byte("x")})
			return release
		},
		"live archive mismatch": func(release Release) Release {
			release.Files[0].Body = []byte("different live manifest")
			return release
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := MaterializeRelease(repositoryRoot, mutate(valid)); err == nil {
				t.Fatal("invalid release was materialized")
			}
			if after := snapshotTree(t, repositoryRoot); !equalSnapshots(before, after) {
				t.Fatal("validation failure changed repository tree")
			}
		})
	}
}

func TestReleaseTreeRejectsImmutableDeletionMutationModeAndUnknownFiles(t *testing.T) {
	base := t.TempDir()
	release := testRelease("catalog-test-data", "manifest", "root", "object")
	if _, err := MaterializeRelease(base, release); err != nil {
		t.Fatal(err)
	}

	tests := map[string]func(string){
		"deletion": func(candidate string) {
			if err := os.Remove(filepath.Join(candidate, filepath.FromSlash(release.Files[2].Path))); err != nil {
				t.Fatal(err)
			}
		},
		"mutation": func(candidate string) {
			if err := os.WriteFile(filepath.Join(candidate, filepath.FromSlash(release.Files[2].Path)), []byte("mutated"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"mode change": func(candidate string) {
			if err := os.Chmod(filepath.Join(candidate, filepath.FromSlash(release.Files[2].Path)), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"unknown file": func(candidate string) {
			writeTreeFile(t, candidate, sourcePath(release.SourceID, "unexpected.txt"), []byte("x"))
		},
		"symlink": func(candidate string) {
			link := filepath.Join(candidate, filepath.FromSlash(sourcePath(release.SourceID, "objects/sha256/aa/"+strings.Repeat("a", 64))))
			if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(candidate, filepath.FromSlash(release.Files[2].Path)), link); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := t.TempDir()
			copyTree(t, base, candidate)
			mutate(candidate)
			if err := VerifyReleaseDiff(base, candidate); err == nil {
				t.Fatal("unsafe release diff was accepted")
			}
		})
	}
}

func TestReleaseTreeRejectsMixedAndUnknownChanges(t *testing.T) {
	release := testRelease("catalog-test-data", "manifest", "root", "object")
	paths := make([]string, 0, len(release.Files))
	for _, file := range release.Files {
		paths = append(paths, file.Path)
	}
	changed, err := ValidateReleaseChangePaths(paths)
	if err != nil || !changed {
		t.Fatalf("release-only paths: changed=%v err=%v", changed, err)
	}
	if _, err := ValidateReleaseChangePaths(append(paths, "README.md")); err == nil {
		t.Fatal("mixed release and non-release paths were accepted")
	}
	if _, err := ValidateReleaseChangePaths([]string{sourcePath(release.SourceID, "notes.txt")}); err == nil {
		t.Fatal("unknown release path was accepted")
	}
	changed, err = ValidateReleaseChangePaths([]string{"catalog/sources/README.md", "docs/ARCHITECTURE.md"})
	if err != nil || changed {
		t.Fatalf("non-release maintenance paths: changed=%v err=%v", changed, err)
	}
}

func testRelease(sourceID, manifest, root, object string) Release {
	objectDigest := sha256HexForTest([]byte(object))
	manifestDigest := sha256HexForTest([]byte(manifest))
	rootDigest := sha256HexForTest([]byte(root))
	version := "00000000000000000001"
	return Release{
		SourceID: sourceID,
		Files: []File{
			{Path: sourcePath(sourceID, "manifest.json"), Body: []byte(manifest)},
			{Path: sourcePath(sourceID, "root.json"), Body: []byte(root)},
			{Path: sourcePath(sourceID, "objects/sha256/"+objectDigest[:2]+"/"+objectDigest), Body: []byte(object)},
			{Path: sourcePath(sourceID, "archive/"+version+"/"+manifestDigest+"/manifest.json"), Body: []byte(manifest)},
			{Path: sourcePath(sourceID, "roots/"+version+"/"+rootDigest+"/root.json"), Body: []byte(root)},
			{Path: sourcePath(sourceID, "packages/"+version+"/"+manifestDigest+"/catalog-test-data.ucp"), Body: []byte("package")},
		},
	}
}

func sourcePath(sourceID, relative string) string {
	return "catalog/sources/" + sourceID + "/" + relative
}

func sha256HexForTest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func writeTreeFile(t *testing.T, root, relative string, content []byte) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
}

func readTreeFile(t *testing.T, root, relative string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func snapshotTree(t *testing.T, root string) map[string][]byte {
	t.Helper()
	result := map[string][]byte{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
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
		result[filepath.ToSlash(relative)] = append([]byte(nil), content...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func equalSnapshots(left, right map[string][]byte) bool {
	if len(left) != len(right) {
		return false
	}
	for path, content := range left {
		if !bytes.Equal(content, right[path]) {
			return false
		}
	}
	return true
}

func copyTree(t *testing.T, source, destination string) {
	t.Helper()
	for relative, content := range snapshotTree(t, source) {
		writeTreeFile(t, destination, relative, content)
		info, err := os.Stat(filepath.Join(source, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(destination, filepath.FromSlash(relative)), info.Mode().Perm()); err != nil {
			t.Fatal(err)
		}
	}
}
