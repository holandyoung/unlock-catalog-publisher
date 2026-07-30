package repository

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPublicMirrorCopiesSignedTreeAndVerifiesReadback(t *testing.T) {
	sourceRoot := t.TempDir()
	mirrorRoot := t.TempDir()
	releases := []Release{
		testRelease("catalog-test-data", "data manifest", "data root", "data object"),
		testRelease("catalog-test-exec", "exec manifest", "exec root", "exec object"),
	}
	wantBytes := int64(0)
	for _, release := range releases {
		if _, err := MaterializeRelease(sourceRoot, release); err != nil {
			t.Fatal(err)
		}
		for _, file := range release.Files {
			wantBytes += int64(len(file.Body))
		}
	}

	report, err := ReplicatePublicMirror(sourceRoot, mirrorRoot)
	if err != nil {
		t.Fatalf("replicate public mirror: %v", err)
	}
	if report.SourceCount != len(releases) || report.FileCount != len(releases)*len(releases[0].Files) || report.FileBytes != wantBytes {
		t.Fatalf("replication report = %+v", report)
	}
	if err := VerifyPublicMirror(sourceRoot, mirrorRoot); err != nil {
		t.Fatalf("verify public mirror: %v", err)
	}
	if got, want := snapshotTree(t, mirrorRoot), snapshotTree(t, sourceRoot); !equalSnapshots(want, got) {
		t.Fatal("mirror bytes differ from the protected release tree")
	}
}

func TestPublicMirrorAdvancesLiveFilesAndPreservesImmutableHistory(t *testing.T) {
	sourceRoot := t.TempDir()
	mirrorRoot := t.TempDir()
	oldRelease := testRelease("catalog-test-data", "old manifest", "old root", "old object")
	if _, err := MaterializeRelease(sourceRoot, oldRelease); err != nil {
		t.Fatal(err)
	}
	if _, err := ReplicatePublicMirror(sourceRoot, mirrorRoot); err != nil {
		t.Fatal(err)
	}
	oldImmutable := readTreeFile(t, mirrorRoot, oldRelease.Files[2].Path)

	newRelease := testRelease("catalog-test-data", "new manifest", "new root", "new object")
	if _, err := MaterializeRelease(sourceRoot, newRelease); err != nil {
		t.Fatal(err)
	}
	if _, err := ReplicatePublicMirror(sourceRoot, mirrorRoot); err != nil {
		t.Fatalf("replicate updated public mirror: %v", err)
	}

	if got := readTreeFile(t, mirrorRoot, oldRelease.Files[2].Path); !bytes.Equal(got, oldImmutable) {
		t.Fatal("mirror update changed prior immutable bytes")
	}
	if err := VerifyPublicMirror(sourceRoot, mirrorRoot); err != nil {
		t.Fatalf("verify updated public mirror: %v", err)
	}
}

func TestPublicMirrorRejectsReadbackByteDrift(t *testing.T) {
	release := testRelease("catalog-test-data", "manifest", "root", "object")
	paths := map[string]string{
		"envelope": release.Files[0].Path,
		"object":   release.Files[2].Path,
		"root":     release.Files[4].Path,
		"package":  release.Files[5].Path,
	}
	for name, relative := range paths {
		t.Run(name, func(t *testing.T) {
			sourceRoot := t.TempDir()
			mirrorRoot := t.TempDir()
			if _, err := MaterializeRelease(sourceRoot, release); err != nil {
				t.Fatal(err)
			}
			if _, err := ReplicatePublicMirror(sourceRoot, mirrorRoot); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(mirrorRoot, filepath.FromSlash(relative)), []byte("drift"), 0o644); err != nil {
				t.Fatal(err)
			}

			if err := VerifyPublicMirror(sourceRoot, mirrorRoot); !errors.Is(err, ErrMirrorMismatch) {
				t.Fatalf("verify drift error = %v, want ErrMirrorMismatch", err)
			}
		})
	}
}

func TestPublicMirrorRejectsChangedImmutablePathWithoutMutation(t *testing.T) {
	sourceRoot := t.TempDir()
	mirrorRoot := t.TempDir()
	release := testRelease("catalog-test-data", "manifest", "root", "object")
	if _, err := MaterializeRelease(sourceRoot, release); err != nil {
		t.Fatal(err)
	}
	if _, err := ReplicatePublicMirror(sourceRoot, mirrorRoot); err != nil {
		t.Fatal(err)
	}
	immutablePath := filepath.Join(mirrorRoot, filepath.FromSlash(release.Files[5].Path))
	if err := os.WriteFile(immutablePath, []byte("changed package"), 0o644); err != nil {
		t.Fatal(err)
	}
	before := snapshotTree(t, mirrorRoot)

	if _, err := ReplicatePublicMirror(sourceRoot, mirrorRoot); !errors.Is(err, ErrImmutableChanged) {
		t.Fatalf("replicate immutable collision error = %v, want ErrImmutableChanged", err)
	}
	if after := snapshotTree(t, mirrorRoot); !equalSnapshots(before, after) {
		t.Fatal("failed replication changed mirror tree")
	}
}

func TestPublicMirrorRejectsUnsafeRootsWithoutMutation(t *testing.T) {
	sourceRoot := t.TempDir()
	release := testRelease("catalog-test-data", "manifest", "root", "object")
	if _, err := MaterializeRelease(sourceRoot, release); err != nil {
		t.Fatal(err)
	}

	t.Run("same root", func(t *testing.T) {
		before := snapshotTree(t, sourceRoot)
		if _, err := ReplicatePublicMirror(sourceRoot, sourceRoot); err == nil {
			t.Fatal("same source and mirror root was accepted")
		}
		if after := snapshotTree(t, sourceRoot); !equalSnapshots(before, after) {
			t.Fatal("unsafe replication changed source tree")
		}
	})

	t.Run("symlink mirror root", func(t *testing.T) {
		realMirror := t.TempDir()
		linkRoot := filepath.Join(t.TempDir(), "mirror")
		if err := os.Symlink(realMirror, linkRoot); err != nil {
			t.Fatal(err)
		}
		if _, err := ReplicatePublicMirror(sourceRoot, linkRoot); err == nil {
			t.Fatal("symlink mirror root was accepted")
		}
		if got := snapshotTree(t, realMirror); len(got) != 0 {
			t.Fatal("unsafe replication changed symlink target")
		}
	})

	t.Run("nested mirror root", func(t *testing.T) {
		mirrorRoot := filepath.Join(sourceRoot, "mirror")
		if err := os.Mkdir(mirrorRoot, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := ReplicatePublicMirror(sourceRoot, mirrorRoot); err == nil {
			t.Fatal("nested mirror root was accepted")
		}
		if got := snapshotTree(t, mirrorRoot); len(got) != 0 {
			t.Fatal("unsafe replication changed nested mirror root")
		}
	})
}

func TestPublicMirrorReadbackFailureRestoresPriorTree(t *testing.T) {
	mirrorRoot := t.TempDir()
	mirrorPrefix := filepath.Join(mirrorRoot, filepath.FromSlash(ReleasePrefix))
	writeTreeFile(t, mirrorRoot, ReleasePrefix+"/prior.txt", []byte("prior"))
	before := snapshotTree(t, mirrorRoot)

	stagingRoot := t.TempDir()
	stagingPrefix := filepath.Join(stagingRoot, "sources")
	writeTreeFile(t, stagingRoot, "sources/next.txt", []byte("next"))
	wantFailure := errors.New("injected readback failure")
	if err := installMirrorPrefix(mirrorPrefix, stagingPrefix, func() error { return wantFailure }); !errors.Is(err, wantFailure) {
		t.Fatalf("install mirror error = %v, want injected readback failure", err)
	}
	if after := snapshotTree(t, mirrorRoot); !equalSnapshots(before, after) {
		t.Fatal("readback failure did not restore prior mirror tree")
	}
}
