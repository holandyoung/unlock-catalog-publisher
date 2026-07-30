package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/holandyoung/unlock-catalog/internal/assemble"
	"github.com/holandyoung/unlock-catalog/internal/catalogv1"
)

func TestMaterializeCommandWritesSignedBytesWithoutCredentials(t *testing.T) {
	release := filepath.Join("..", "..", "fixtures", "v1", "signed", "positive", "data", "release")
	repositoryRoot := t.TempDir()
	artifact, err := loadRelease(release)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := run([]string{"materialize", "--release", release, "--repository", repositoryRoot}, func(string) string {
		return ""
	}, &stdout, &stderr); err != nil {
		t.Fatalf("materialize: %v", err)
	}
	sourceRoot := filepath.Join(repositoryRoot, "catalog", "sources", "unlock-official-linux-amd64-static")
	for _, relative := range []string{"manifest.json", "root.json"} {
		if _, err := os.Stat(filepath.Join(repositoryRoot, "catalog", "sources", "unlock-official-linux-amd64-static", filepath.FromSlash(relative))); err != nil {
			t.Fatalf("materialized %s: %v", relative, err)
		}
	}
	archives, err := filepath.Glob(filepath.Join(sourceRoot, "archive", "00000000000000000001", "*", "manifest.json"))
	if err != nil || len(archives) != 1 {
		t.Fatalf("materialized manifest archives = %v err=%v", archives, err)
	}
	live, err := os.ReadFile(filepath.Join(sourceRoot, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	archived, err := os.ReadFile(archives[0])
	if err != nil || !bytes.Equal(live, archived) {
		t.Fatalf("archive bytes differ: err=%v", err)
	}
	if !strings.Contains(stdout.String(), `"sourceId":"unlock-official-linux-amd64-static"`) ||
		!strings.Contains(stdout.String(), `"fileCount"`) {
		t.Fatalf("materialize report = %q", stdout.String())
	}
	for _, file := range artifact.Files {
		materialized, err := os.ReadFile(filepath.Join(repositoryRoot, filepath.FromSlash(file.Path)))
		if err != nil {
			t.Fatalf("read materialized %s: %v", file.Path, err)
		}
		if !bytes.Equal(materialized, file.Body) {
			t.Fatalf("materializer changed signed bytes at %s", file.Path)
		}
	}
}

func TestMaterializeCommandValidationFailureLeavesRepositoryUnchanged(t *testing.T) {
	release := filepath.Join("..", "..", "fixtures", "v1", "signed", "positive", "data", "release")
	repositoryRoot := t.TempDir()
	var stdout, stderr bytes.Buffer
	if err := run([]string{"materialize", "--release", release, "--repository", repositoryRoot}, func(string) string {
		return ""
	}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	want := snapshotDirectory(t, repositoryRoot)

	tests := map[string]func(string){
		"extra file": func(root string) {
			if err := os.WriteFile(filepath.Join(root, "notes.txt"), []byte("unexpected"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"duplicate package": func(root string) {
			packagePath := filepath.Join(root, "unlock-catalog-package-v1.tar.zst")
			content, err := os.ReadFile(packagePath)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "duplicate.tar.zst"), content, 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"symlink": func(root string) {
			rootPath := filepath.Join(root, "root.json")
			if err := os.Remove(rootPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("manifest.json", rootPath); err != nil {
				t.Fatal(err)
			}
		},
		"signed byte mutation": func(root string) {
			manifestPath := filepath.Join(root, "manifest.json")
			content, err := os.ReadFile(manifestPath)
			if err != nil {
				t.Fatal(err)
			}
			content[len(content)/2] ^= 1
			if err := os.WriteFile(manifestPath, content, 0o644); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			invalid := t.TempDir()
			copyDirectory(t, release, invalid)
			mutate(invalid)
			stdout.Reset()
			stderr.Reset()
			if err := run([]string{"materialize", "--release", invalid, "--repository", repositoryRoot}, func(string) string {
				return ""
			}, &stdout, &stderr); err == nil {
				t.Fatal("invalid assembled release was materialized")
			}
			if got := snapshotDirectory(t, repositoryRoot); !equalDirectorySnapshots(want, got) {
				t.Fatal("failed materialization changed the repository")
			}
		})
	}
}

func TestReleaseTreeChecksCurrentSemanticClosure(t *testing.T) {
	release := filepath.Join("..", "..", "fixtures", "v1", "signed", "positive", "data", "release")
	baseRoot := t.TempDir()
	repositoryRoot := t.TempDir()
	var stdout, stderr bytes.Buffer
	if err := run([]string{"materialize", "--release", release, "--repository", repositoryRoot}, func(string) string {
		return ""
	}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	changed := "catalog/sources/unlock-official-linux-amd64-static/manifest.json"
	stdout.Reset()
	if err := run([]string{"verify-release", "--base", baseRoot, "--repository", repositoryRoot, "--changed-file", changed}, func(string) string {
		return ""
	}, &stdout, &stderr); err != nil {
		t.Fatalf("verify materialized release: %v", err)
	}
	if !strings.Contains(stdout.String(), `"verified":true`) {
		t.Fatalf("verify report = %q", stdout.String())
	}

	manifestBytes, err := os.ReadFile(filepath.Join(repositoryRoot, "catalog", "sources", "unlock-official-linux-amd64-static", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest assemble.SignedManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	sourceRoot := filepath.Join(repositoryRoot, "catalog", "sources", manifest.Signed.SourceID)
	manifestArchives, err := filepath.Glob(filepath.Join(sourceRoot, "archive", "*", "*", "manifest.json"))
	if err != nil || len(manifestArchives) != 1 {
		t.Fatalf("manifest archives = %v err=%v", manifestArchives, err)
	}
	packagePaths, err := filepath.Glob(filepath.Join(sourceRoot, "packages", "*", "*", "unlock-catalog-package-v1.tar.zst"))
	if err != nil || len(packagePaths) != 1 {
		t.Fatalf("packages = %v err=%v", packagePaths, err)
	}
	rootArchives, err := filepath.Glob(filepath.Join(sourceRoot, "roots", "*", "*", "root.json"))
	if err != nil || len(rootArchives) != 1 {
		t.Fatalf("root archives = %v err=%v", rootArchives, err)
	}
	tests := map[string]string{
		"referenced object": filepath.Join(sourceRoot, filepath.FromSlash(manifest.Signed.Artifacts[0].Path)),
		"manifest archive":  manifestArchives[0],
		"root archive":      rootArchives[0],
		"package":           packagePaths[0],
	}
	for name, removedPath := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := t.TempDir()
			copyDirectory(t, repositoryRoot, candidate)
			relative, err := filepath.Rel(repositoryRoot, removedPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(candidate, relative)); err != nil {
				t.Fatal(err)
			}
			stdout.Reset()
			if err := run([]string{"verify-release", "--base", baseRoot, "--repository", candidate, "--changed-file", changed}, func(string) string {
				return ""
			}, &stdout, &stderr); err == nil {
				t.Fatalf("release with missing %s was accepted", name)
			}
		})
	}
}

func TestReleaseTreeRejectsManifestRootAndRevocationRollback(t *testing.T) {
	revocation := catalogv1.Revocation{
		RevocationID: "revocation-a", Kind: "artifact", TargetID: "artifact-a", Version: 2, Reason: "withdrawn",
	}
	state := func(manifestVersion, rootVersion uint64, manifestBytes, rootBytes string, revocations []catalogv1.Revocation) publishedRelease {
		return publishedRelease{
			manifest:      assemble.SignedManifest{Signed: catalogv1.Manifest{Version: manifestVersion, Revocations: revocations}},
			root:          assemble.SignedRoot{Signed: assemble.TrustRoot{Version: rootVersion}},
			manifestBytes: []byte(manifestBytes), rootBytes: []byte(rootBytes),
		}
	}
	base := map[string]publishedRelease{"source-a": state(2, 3, "manifest-2", "root-3", []catalogv1.Revocation{revocation})}
	if err := verifyForwardOnly(nil, base); err != nil {
		t.Fatalf("new source on empty base: %v", err)
	}
	if err := verifyForwardOnly(base, base); err != nil {
		t.Fatalf("unchanged source: %v", err)
	}
	tests := map[string]publishedRelease{
		"manifest version rollback": state(1, 3, "manifest-1", "root-3", []catalogv1.Revocation{revocation}),
		"manifest version reuse":    state(2, 3, "changed", "root-3", []catalogv1.Revocation{revocation}),
		"root version rollback":     state(2, 2, "manifest-2", "root-2", []catalogv1.Revocation{revocation}),
		"root version reuse":        state(2, 3, "manifest-2", "changed", []catalogv1.Revocation{revocation}),
		"revocation removal":        state(3, 4, "manifest-3", "root-4", nil),
		"revocation weakening": state(3, 4, "manifest-3", "root-4", []catalogv1.Revocation{{
			RevocationID: revocation.RevocationID, Kind: revocation.Kind, TargetID: revocation.TargetID,
			Version: 1, Reason: revocation.Reason,
		}}),
	}
	for name, candidate := range tests {
		t.Run(name, func(t *testing.T) {
			if err := verifyForwardOnly(base, map[string]publishedRelease{"source-a": candidate}); err == nil {
				t.Fatal("rollback was accepted")
			}
		})
	}
}

func TestReleaseTreeAcceptsThresholdSignedRootBridge(t *testing.T) {
	fixtureRoot := filepath.Join("..", "..", "fixtures", "v1", "signed", "positive", "data")
	repositoryRoot := t.TempDir()
	var stdout, stderr bytes.Buffer
	if err := run([]string{"materialize", "--release", filepath.Join(fixtureRoot, "release"), "--repository", repositoryRoot}, func(string) string {
		return ""
	}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	candidate, err := verifyPublishedRepository(repositoryRoot)
	if err != nil {
		t.Fatal(err)
	}
	next := candidate["unlock-official-linux-amd64-static"]
	currentRootBytes, err := os.ReadFile(filepath.Join(fixtureRoot, "current-root.json"))
	if err != nil {
		t.Fatal(err)
	}
	var currentRoot assemble.TrustRoot
	if err := json.Unmarshal(currentRootBytes, &currentRoot); err != nil {
		t.Fatal(err)
	}
	prior := next
	prior.root.Signed = currentRoot
	prior.rootBytes = currentRootBytes
	if err := verifyForwardOnly(
		map[string]publishedRelease{next.manifest.Signed.SourceID: prior},
		map[string]publishedRelease{next.manifest.Signed.SourceID: next},
	); err != nil {
		t.Fatalf("valid R1-to-R2 bridge: %v", err)
	}
}

func TestDeployRetiredWorkflowHasNoWriterSignerOrObjectStoreCredential(t *testing.T) {
	workflow, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	content := string(workflow)
	for _, required := range []string{
		"pull_request", "verify-release", "permissions:", "contents: read",
		"github.event.pull_request.base.sha", ".release-base/.github/workflows/release.yml",
	} {
		if !strings.Contains(content, required) {
			t.Errorf("release workflow missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"catalog-signer", "catalog-assembler", "R" + "2_", "aws", "secrets.", "git push", "contents: write",
	} {
		if strings.Contains(content, forbidden) {
			t.Errorf("release workflow contains forbidden capability %q", forbidden)
		}
	}
}

func TestDeployRetiredProductionSymbolsAndDependenciesAreAbsent(t *testing.T) {
	root := filepath.Join("..", "..")
	for _, retired := range []string{
		filepath.Join(root, "internal", "repository", "r"+"2.go"),
		filepath.Join(root, "internal", "repository", "store.go"),
		filepath.Join(root, "cmd", "catalog-publisher", "deploy.go"),
		filepath.Join(root, ".github", "workflows", "deploy.yml"),
	} {
		if _, err := os.Lstat(retired); !os.IsNotExist(err) {
			t.Fatalf("retired production path remains: %s", retired)
		}
	}
	module, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"github.com/" + "aws/", "service/" + "s3"} {
		if bytes.Contains(module, []byte(forbidden)) {
			t.Fatalf("retired dependency remains: %s", forbidden)
		}
	}
}

func copyDirectory(t *testing.T, source, destination string) {
	t.Helper()
	err := filepath.Walk(source, func(itemPath string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, itemPath)
		if err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		target := filepath.Join(destination, relative)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm())
		}
		content, err := os.ReadFile(itemPath)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return os.WriteFile(target, content, info.Mode().Perm())
	})
	if err != nil {
		t.Fatal(err)
	}
}

func snapshotDirectory(t *testing.T, root string) map[string]string {
	t.Helper()
	result := map[string]string{}
	err := filepath.Walk(root, func(itemPath string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, itemPath)
		if err != nil {
			return err
		}
		if relative == "." || info.IsDir() {
			return nil
		}
		content, err := os.ReadFile(itemPath)
		if err != nil {
			return err
		}
		result[filepath.ToSlash(relative)] = fmt.Sprintf("%o:%x", info.Mode(), content)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func equalDirectorySnapshots(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for name, value := range left {
		if right[name] != value {
			return false
		}
	}
	return true
}
