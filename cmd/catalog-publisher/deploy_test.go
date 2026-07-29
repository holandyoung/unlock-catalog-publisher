package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/holandyoung/unlock-catalog-publisher/internal/repository"
)

func TestDeployReleasePublishesVerifiedImmutablesBeforeLiveManifest(t *testing.T) {
	release := filepath.Join("..", "..", "fixtures", "v1", "signed", "positive", "data", "release")
	artifact, err := loadRelease(release, "v1/sources")
	if err != nil {
		t.Fatalf("loadRelease: %v", err)
	}
	store := newDeployStore()
	old := []byte("{\"signed\":{\"version\":0}}")
	store.seed(artifact.LiveManifest.Key, old, "\"old\"")
	expected := "\"old\""
	report, err := deployRelease(context.Background(), store, artifact, &expected)
	if err != nil {
		t.Fatalf("deployRelease: %v", err)
	}
	if report.LiveETag == "" || report.SourceID != "unlock-official-linux-amd64-static" || report.ObjectCount != len(artifact.Immutables) {
		t.Fatalf("deploy report = %+v", report)
	}
	if len(store.putOrder) == 0 || store.putOrder[len(store.putOrder)-1] != artifact.LiveManifest.Key {
		t.Fatalf("put order does not end with live manifest: %v", store.putOrder)
	}
	for _, object := range artifact.Immutables {
		if indexOf(store.putOrder, object.Key) < 0 || indexOf(store.putOrder, object.Key) >= len(store.putOrder)-1 {
			t.Fatalf("immutable %q was not verified before live manifest: %v", object.Key, store.putOrder)
		}
	}
}

func TestDeployReleaseFailuresKeepOldLivePointer(t *testing.T) {
	release := filepath.Join("..", "..", "fixtures", "v1", "signed", "positive", "data", "release")
	artifact, err := loadRelease(release, "v1/sources")
	if err != nil {
		t.Fatal(err)
	}
	old := []byte("{\"signed\":{\"version\":0}}")

	tests := map[string]func(*deployStore, *string){
		"immutable collision": func(store *deployStore, _ *string) {
			store.seed(artifact.Immutables[0].Key, []byte("different"), "\"collision\"")
		},
		"partial upload": func(store *deployStore, _ *string) {
			store.failKey = artifact.Immutables[1].Key
		},
		"readback digest mismatch": func(store *deployStore, _ *string) {
			store.corruptGetKey = artifact.Immutables[0].Key
		},
		"lost update": func(_ *deployStore, expected *string) {
			*expected = "\"stale\""
		},
	}
	for name, setup := range tests {
		t.Run(name, func(t *testing.T) {
			store := newDeployStore()
			store.seed(artifact.LiveManifest.Key, old, "\"old\"")
			expected := "\"old\""
			setup(store, &expected)
			if _, err := deployRelease(context.Background(), store, artifact, &expected); err == nil {
				t.Fatal("deployRelease accepted injected failure")
			}
			live := store.objects[artifact.LiveManifest.Key]
			if string(live.body) != string(old) || live.etag != "\"old\"" {
				t.Fatalf("failure changed old live pointer: body=%q etag=%q", live.body, live.etag)
			}
		})
	}
}

func TestDeployReleaseRetriesAfterCrashWithoutOverwritingImmutableBytes(t *testing.T) {
	release := filepath.Join("..", "..", "fixtures", "v1", "signed", "positive", "data", "release")
	artifact, err := loadRelease(release, "v1/sources")
	if err != nil {
		t.Fatal(err)
	}
	store := newDeployStore()
	old := []byte("{\"signed\":{\"version\":0}}")
	store.seed(artifact.LiveManifest.Key, old, "\"old\"")
	store.failKey = artifact.Immutables[2].Key
	expected := "\"old\""
	if _, err := deployRelease(context.Background(), store, artifact, &expected); err == nil {
		t.Fatal("first deploy did not stop at injected crash")
	}
	store.failKey = ""
	if _, err := deployRelease(context.Background(), store, artifact, &expected); err != nil {
		t.Fatalf("crash retry: %v", err)
	}
	if string(store.objects[artifact.LiveManifest.Key].body) != string(artifact.LiveManifest.Body) {
		t.Fatal("crash retry did not publish live manifest")
	}
}

func TestDeployRootPublishesArchiveBeforeLiveRoot(t *testing.T) {
	release := filepath.Join("..", "..", "fixtures", "v1", "signed", "positive", "data", "release")
	artifact, err := loadRelease(release, "v1/sources")
	if err != nil {
		t.Fatal(err)
	}
	store := newDeployStore()
	old := []byte("{\"signed\":{\"version\":1}}")
	store.seed(artifact.LiveRoot.Key, old, "\"old-root\"")
	expected := "\"old-root\""
	if _, err := deployRoot(context.Background(), store, artifact, &expected); err != nil {
		t.Fatalf("deployRoot: %v", err)
	}
	if len(store.putOrder) != 2 || store.putOrder[0] != artifact.RootArchive.Key || store.putOrder[1] != artifact.LiveRoot.Key {
		t.Fatalf("root put order = %v", store.putOrder)
	}

	failed := newDeployStore()
	failed.seed(artifact.LiveRoot.Key, old, "\"old-root\"")
	stale := "\"stale\""
	if _, err := deployRoot(context.Background(), failed, artifact, &stale); err == nil {
		t.Fatal("deployRoot accepted stale ETag")
	}
	if got := failed.objects[artifact.LiveRoot.Key]; string(got.body) != string(old) || got.etag != "\"old-root\"" {
		t.Fatalf("failed root CAS changed live root: %+v", got)
	}
}

func TestDeployPackageSizeIsBoundedBeforeUpload(t *testing.T) {
	if err := validateDeployPackageSize(repository.MaxReadbackBytes); err != nil {
		t.Fatalf("maximum package size rejected: %v", err)
	}
	if err := validateDeployPackageSize(repository.MaxReadbackBytes + 1); err == nil {
		t.Fatal("oversized package accepted")
	}
}

func TestDeployWorkflowConsumesOnlyAssembledArtifacts(t *testing.T) {
	workflow, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "deploy.yml"))
	if err != nil {
		t.Fatal(err)
	}
	content := string(workflow)
	for _, required := range []string{
		"actions/download-artifact@", "go run ./cmd/catalog-publisher deploy",
		"secrets.R2_ACCESS_KEY_ID", "secrets.R2_SECRET_ACCESS_KEY",
	} {
		if !strings.Contains(content, required) {
			t.Errorf("deploy workflow missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"catalog-signer", "catalog-assembler", "SOURCE_DATE_EPOCH",
		"catalog-publisher candidate", "signing-request",
	} {
		if strings.Contains(content, forbidden) {
			t.Errorf("deploy workflow contains forbidden capability %q", forbidden)
		}
	}
	policy, err := os.ReadFile(filepath.Join("..", "..", "deploy", "policy.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"If-None-Match: *", "If-Match", "prefix-scoped", "manifest.json",
		"root.json", "Content-MD5", "Accept-Encoding: identity",
	} {
		if !strings.Contains(string(policy), required) {
			t.Errorf("deploy policy missing %q", required)
		}
	}
}

type deployObject struct {
	body    []byte
	etag    string
	request repository.PutRequest
}

type deployStore struct {
	objects       map[string]deployObject
	putOrder      []string
	failKey       string
	corruptGetKey string
}

func newDeployStore() *deployStore { return &deployStore{objects: map[string]deployObject{}} }

func (store *deployStore) seed(key string, body []byte, etag string) {
	store.objects[key] = deployObject{body: append([]byte(nil), body...), etag: etag}
}

func (store *deployStore) PutObject(_ context.Context, request repository.PutRequest) (repository.PutResult, error) {
	store.putOrder = append(store.putOrder, request.Key)
	if request.Key == store.failKey {
		return repository.PutResult{}, errors.New("injected partial upload")
	}
	prior, exists := store.objects[request.Key]
	if request.Condition.IfNoneMatch && exists {
		return repository.PutResult{}, repository.ErrPreconditionFailed
	}
	if request.Condition.IfMatch != "" && (!exists || prior.etag != request.Condition.IfMatch) {
		return repository.PutResult{}, repository.ErrPreconditionFailed
	}
	etag := "\"etag-" + request.SHA256[:12] + "\""
	store.objects[request.Key] = deployObject{body: append([]byte(nil), request.Body...), etag: etag, request: request}
	return repository.PutResult{ETag: etag}, nil
}

func (store *deployStore) HeadObject(_ context.Context, key string) (repository.Metadata, error) {
	object, ok := store.objects[key]
	if !ok {
		return repository.Metadata{}, repository.ErrNotFound
	}
	return deployMetadata(object), nil
}

func (store *deployStore) GetObject(_ context.Context, request repository.GetRequest) (repository.GetResult, error) {
	object, ok := store.objects[request.Key]
	if !ok {
		return repository.GetResult{}, repository.ErrNotFound
	}
	result := repository.GetResult{Metadata: deployMetadata(object), Body: append([]byte(nil), object.body...)}
	if request.Range != "" {
		result.Body = append([]byte(nil), object.body[:1]...)
		result.ContentRange = "bytes 0-0/" + strconv.Itoa(len(object.body))
	}
	if request.Range == "" && request.Key == store.corruptGetKey {
		result.Body[0] ^= 0xff
	}
	return result, nil
}

func deployMetadata(object deployObject) repository.Metadata {
	return repository.Metadata{
		ETag: object.etag, Length: int64(len(object.body)), SHA256: object.request.SHA256,
		ContentType: object.request.ContentType, CacheControl: object.request.CacheControl,
		ContentEncoding: object.request.ContentEncoding, AcceptRanges: "bytes",
	}
}

func indexOf(values []string, expected string) int {
	for index, value := range values {
		if value == expected {
			return index
		}
	}
	return -1
}
