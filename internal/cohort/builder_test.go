package cohort

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/holandyoung/unlock-catalog/internal/catalogv1"
	"github.com/holandyoung/unlock-catalog/internal/policy"
	"gopkg.in/yaml.v3"
)

type sourceFixture struct {
	root       string
	sourceFile string
	objectPath string
	source     catalogv1.Source
}

func newSourceFixture(t *testing.T) sourceFixture {
	t.Helper()
	content := []byte(`{"fixture":"catalog-data"}`)
	sum := sha256.Sum256(content)
	digest := hex.EncodeToString(sum[:])
	relative := "objects/sha256/" + digest[:2] + "/" + digest
	root := filepath.Join(t.TempDir(), policy.DataSourceID)
	objectPath := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(objectPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(objectPath, content, 0o644); err != nil {
		t.Fatal(err)
	}
	source := catalogv1.Source{
		SchemaVersion: 1, SourceID: policy.DataSourceID, Version: 7, ValidForSeconds: 14 * 24 * 60 * 60,
		MinCoreProtocol: 1, MaxCoreProtocol: 2, MinCoreVersion: "1.0.0", MaxCoreVersion: "2.0.0",
		CompatibilityEpoch: 1,
		Permissions: []catalogv1.Permission{
			catalogv1.PermissionMetadata,
			catalogv1.PermissionDetectionData,
			catalogv1.PermissionRoutingData,
		},
		Cohort: catalogv1.Cohort{OS: "linux", Arch: "amd64", ABI: "static"},
		Entries: []catalogv1.Entry{{
			EntryID: "example", DisplayComponentID: "example-display", DisplayName: "Example",
			Family: catalogv1.FamilyDefinition{
				Name: "example", DisplayName: "Example", DefaultEngine: "mediaunlocktest",
				DefaultVariant: "global", RoutingEntry: "example",
				Variants: map[string]catalogv1.VariantDefinition{
					"global": {ID: "global", RequiredSlots: []string{"availability"}, Bindings: []catalogv1.BindingDefinition{{ID: "example-check", Provider: "example", Slots: []string{"availability"}}}},
				},
				PinPolicy: catalogv1.PinPolicy{ComponentID: "example-check", SourceSlot: "availability", AcceptedVerdicts: []string{"unlocked"}},
			},
			Metadata:  []catalogv1.ArtifactComponent{{ComponentID: "example-metadata", ArtifactID: "example-object"}},
			Routing:   []catalogv1.RoutingComponent{{ComponentID: "example-route", Rule: &catalogv1.RoutingRule{Kind: "domain", Value: "example.test"}}},
			Detection: []catalogv1.DetectionComponent{{ComponentID: "example-check"}},
		}},
		Artifacts: []catalogv1.ArtifactDescriptor{{
			ArtifactID: "example-object", EntryID: "example", Permission: catalogv1.PermissionMetadata,
			MediaType: "application/json", Path: relative, SHA256: digest, Length: int64(len(content)),
		}},
		Revocations: []catalogv1.Revocation{},
	}
	fixture := sourceFixture{root: root, sourceFile: filepath.Join(root, "source.yaml"), objectPath: objectPath, source: source}
	fixture.writeSource(t)
	return fixture
}

func (fixture sourceFixture) writeSource(t *testing.T) {
	t.Helper()
	content, err := yaml.Marshal(fixture.source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.sourceFile, content, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestBuildCandidateIsDeterministicAndUnsigned(t *testing.T) {
	fixture := newSourceFixture(t)
	epoch := time.Unix(1_785_312_000, 0).UTC()
	firstRoot := filepath.Join(t.TempDir(), "first")
	secondRoot := filepath.Join(t.TempDir(), "second")

	first, err := BuildCandidate(fixture.sourceFile, firstRoot, epoch)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildCandidate(fixture.sourceFile, secondRoot, epoch)
	if err != nil {
		t.Fatal(err)
	}
	if first.PayloadSHA256 != second.PayloadSHA256 {
		t.Fatalf("payload digest mismatch %s != %s", first.PayloadSHA256, second.PayloadSHA256)
	}
	compareTrees(t, first.Directory, second.Directory)

	payload, err := os.ReadFile(filepath.Join(first.Directory, ManifestPayloadName))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(payload, []byte(`"signatures"`)) || bytes.Contains(payload, []byte(`"deploy"`)) {
		t.Fatalf("unsigned candidate contains forbidden capability: %s", payload)
	}
	var manifest catalogv1.Manifest
	if err := json.Unmarshal(payload, &manifest); err != nil {
		t.Fatal(err)
	}
	if !manifest.PublishedAt.Equal(epoch) || manifest.SourceID != policy.DataSourceID {
		t.Fatalf("manifest identity/time = %s %s", manifest.SourceID, manifest.PublishedAt)
	}
	requestBytes, err := os.ReadFile(filepath.Join(first.Directory, SigningRequestName))
	if err != nil {
		t.Fatal(err)
	}
	var request catalogv1.SigningRequest
	if err := json.Unmarshal(requestBytes, &request); err != nil {
		t.Fatal(err)
	}
	if request.PayloadSHA256 != first.PayloadSHA256 || request.SourceID != manifest.SourceID || request.Version != manifest.Version || request.PolicyVersion != policy.PolicyVersion {
		t.Fatalf("signing request is not bound to payload: %+v", request)
	}
}

func TestBuildCandidateRejectsObjectMismatchAndUnsafeFiles(t *testing.T) {
	for name, mutate := range map[string]func(t *testing.T, fixture *sourceFixture){
		"digest mismatch": func(t *testing.T, fixture *sourceFixture) {
			fake := strings.Repeat("b", 64)
			fixture.source.Artifacts[0].SHA256 = fake
			fixture.source.Artifacts[0].Path = "objects/sha256/bb/" + fake
			fixture.objectPath = filepath.Join(fixture.root, filepath.FromSlash(fixture.source.Artifacts[0].Path))
			if err := os.MkdirAll(filepath.Dir(fixture.objectPath), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(fixture.objectPath, []byte("not-the-declared-digest"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"length mismatch": func(_ *testing.T, fixture *sourceFixture) {
			fixture.source.Artifacts[0].Length++
		},
		"symlink object": func(t *testing.T, fixture *sourceFixture) {
			if err := os.Remove(fixture.objectPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("source.yaml", fixture.objectPath); err != nil {
				t.Fatal(err)
			}
		},
		"executable file mode": func(t *testing.T, fixture *sourceFixture) {
			if err := os.Chmod(fixture.objectPath, 0o755); err != nil {
				t.Fatal(err)
			}
		},
		"symlink parent directory": func(t *testing.T, fixture *sourceFixture) {
			content, err := os.ReadFile(fixture.objectPath)
			if err != nil {
				t.Fatal(err)
			}
			targetRoot := filepath.Join(t.TempDir(), "objects")
			targetPath := filepath.Join(targetRoot, filepath.FromSlash(strings.TrimPrefix(fixture.source.Artifacts[0].Path, "objects/")))
			if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(targetPath, content, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.RemoveAll(filepath.Join(fixture.root, "objects")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(targetRoot, filepath.Join(fixture.root, "objects")); err != nil {
				t.Fatal(err)
			}
		},
		"undeclared file": func(t *testing.T, fixture *sourceFixture) {
			if err := os.WriteFile(filepath.Join(fixture.root, "build.sh"), []byte("never execute me\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newSourceFixture(t)
			mutate(t, &fixture)
			fixture.writeSource(t)
			output := filepath.Join(t.TempDir(), "candidate")
			if _, err := BuildCandidate(fixture.sourceFile, output, time.Unix(1_785_312_000, 0).UTC()); err == nil {
				t.Fatal("unsafe or mismatched object was accepted")
			}
			if entries, err := os.ReadDir(output); err == nil && len(entries) != 0 {
				t.Fatalf("failed build left partial output: %v", entries)
			}
		})
	}
}

func TestCheckedSourcesMatchGoldenCandidate(t *testing.T) {
	sources, err := filepath.Glob(filepath.Join("..", "..", "catalog", "definitions", "*", "source.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 2 {
		t.Fatalf("checked source count = %d want 2", len(sources))
	}
	output := filepath.Join(t.TempDir(), "candidate")
	epoch := time.Unix(1_785_312_000, 0).UTC()
	for _, source := range sources {
		if _, err := BuildCandidate(source, output, epoch); err != nil {
			t.Fatalf("build checked source %s: %v", source, err)
		}
	}
	compareTrees(t, output, filepath.Join("..", "..", "fixtures", "v1", "candidate", "valid"))
}

func compareTrees(t *testing.T, first, second string) {
	t.Helper()
	type item struct {
		path string
		mode fs.FileMode
		data []byte
	}
	read := func(root string) []item {
		var items []item
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			items = append(items, item{path: filepath.ToSlash(relative), mode: info.Mode(), data: content})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		sort.Slice(items, func(i, j int) bool { return items[i].path < items[j].path })
		return items
	}
	got, want := read(first), read(second)
	if len(got) != len(want) {
		t.Fatalf("tree file count %d != %d", len(got), len(want))
	}
	for index := range got {
		if got[index].path != want[index].path || got[index].mode != want[index].mode || !bytes.Equal(got[index].data, want[index].data) {
			t.Fatalf("tree mismatch at %d: %+v != %+v", index, got[index], want[index])
		}
	}
}
