package repository

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestDeployStorePutImmutableIsConditionalIdempotentAndVerified(t *testing.T) {
	ctx := context.Background()
	store := newMemoryStore()
	object := Object{Key: "v1/source/objects/sha256/aa/aabb", Body: []byte("immutable"), ContentType: "application/json"}
	stored, err := PutImmutable(ctx, store, object)
	if err != nil {
		t.Fatalf("PutImmutable: %v", err)
	}
	if stored.ETag == "" || len(store.puts) != 1 || !store.puts[0].Condition.IfNoneMatch || store.puts[0].Condition.IfMatch != "" {
		t.Fatalf("immutable conditional request = %+v", store.puts)
	}
	if store.puts[0].CacheControl != ImmutableCacheControl || store.puts[0].ContentEncoding != "" {
		t.Fatalf("immutable headers = %+v", store.puts[0])
	}
	if store.puts[0].SHA256 != digestHex(object.Body) || store.puts[0].ContentMD5 != digestMD5(object.Body) {
		t.Fatal("immutable upload did not bind SHA256 and Content-MD5")
	}
	if got := strings.Join(store.reads, ","); got != "head:"+object.Key+",get:"+object.Key+",range:"+object.Key {
		t.Fatalf("immutable readback order = %q", got)
	}

	store.resetCalls()
	if _, err := PutImmutable(ctx, store, object); err != nil {
		t.Fatalf("idempotent retry: %v", err)
	}
	if len(store.puts) != 1 || len(store.reads) != 3 {
		t.Fatalf("idempotent retry calls: puts=%d reads=%v", len(store.puts), store.reads)
	}

	store.objects[object.Key] = memoryObject{body: []byte("collision"), request: store.puts[0], etag: "\"collision\""}
	if _, err := PutImmutable(ctx, store, object); !errors.Is(err, ErrImmutableCollision) {
		t.Fatalf("collision error = %v", err)
	}
}

func TestDeployStoreRejectsReadbackDrift(t *testing.T) {
	tests := map[string]func(*memoryStore){
		"head digest": func(store *memoryStore) {
			store.mutateHead = func(meta *Metadata) { meta.SHA256 = strings.Repeat("0", 64) }
		},
		"head content type": func(store *memoryStore) { store.mutateHead = func(meta *Metadata) { meta.ContentType = "text/plain" } },
		"content encoding":  func(store *memoryStore) { store.mutateHead = func(meta *Metadata) { meta.ContentEncoding = "gzip" } },
		"accept ranges":     func(store *memoryStore) { store.mutateHead = func(meta *Metadata) { meta.AcceptRanges = "none" } },
		"get digest":        func(store *memoryStore) { store.mutateGet = func(result *GetResult) { result.Body[0] ^= 0xff } },
		"get header": func(store *memoryStore) {
			store.mutateGet = func(result *GetResult) { result.ContentType = "text/plain" }
		},
		"range bytes": func(store *memoryStore) { store.mutateRange = func(result *GetResult) { result.Body = []byte("x") } },
		"content range": func(store *memoryStore) {
			store.mutateRange = func(result *GetResult) { result.ContentRange = "bytes 1-1/9" }
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			store := newMemoryStore()
			mutate(store)
			_, err := PutImmutable(context.Background(), store, Object{
				Key:  "v1/source/archive/00000000000000000001/digest/manifest.json",
				Body: []byte("immutable"), ContentType: "application/json",
			})
			if !errors.Is(err, ErrReadbackMismatch) {
				t.Fatalf("readback drift error = %v", err)
			}
		})
	}
}

func TestDeployStoreCompareAndSwapLiveUsesExactETag(t *testing.T) {
	ctx := context.Background()
	store := newMemoryStore()
	key := "v1/source/manifest.json"
	old := Object{Key: key, Body: []byte("old"), ContentType: "application/json"}
	store.seed(old, "\"old-etag\"", LiveCacheControl)

	stale := "\"stale\""
	if _, err := CompareAndSwapLive(ctx, store, Object{Key: key, Body: []byte("new"), ContentType: "application/json"}, &stale); !errors.Is(err, ErrLostUpdate) {
		t.Fatalf("lost update error = %v", err)
	}
	if got := string(store.objects[key].body); got != "old" {
		t.Fatalf("lost update changed live bytes to %q", got)
	}

	expected := "\"old-etag\""
	stored, err := CompareAndSwapLive(ctx, store, Object{Key: key, Body: []byte("new"), ContentType: "application/json"}, &expected)
	if err != nil {
		t.Fatalf("CompareAndSwapLive: %v", err)
	}
	request := store.puts[len(store.puts)-1]
	if request.Condition.IfMatch != expected || request.Condition.IfNoneMatch || request.CacheControl != LiveCacheControl {
		t.Fatalf("live conditional request = %+v", request)
	}
	if stored.ETag == "" || string(store.objects[key].body) != "new" {
		t.Fatal("live CAS did not store new bytes")
	}

	initialStore := newMemoryStore()
	if _, err := CompareAndSwapLive(ctx, initialStore, Object{Key: key, Body: []byte("first"), ContentType: "application/json"}, nil); err != nil {
		t.Fatalf("initial live create: %v", err)
	}
	if !initialStore.puts[0].Condition.IfNoneMatch {
		t.Fatal("initial live create omitted If-None-Match")
	}
}

type memoryObject struct {
	body    []byte
	request PutRequest
	etag    string
}

type memoryStore struct {
	objects     map[string]memoryObject
	puts        []PutRequest
	reads       []string
	failPut     func(PutRequest) error
	mutateHead  func(*Metadata)
	mutateGet   func(*GetResult)
	mutateRange func(*GetResult)
}

func newMemoryStore() *memoryStore {
	return &memoryStore{objects: map[string]memoryObject{}}
}

func (store *memoryStore) resetCalls() {
	store.puts = nil
	store.reads = nil
}

func (store *memoryStore) seed(object Object, etag, cacheControl string) {
	request := PutRequest{Object: object, CacheControl: cacheControl, SHA256: digestHex(object.Body), ContentMD5: digestMD5(object.Body)}
	store.objects[object.Key] = memoryObject{body: append([]byte(nil), object.Body...), request: request, etag: etag}
}

func (store *memoryStore) PutObject(_ context.Context, request PutRequest) (PutResult, error) {
	store.puts = append(store.puts, request)
	if store.failPut != nil {
		if err := store.failPut(request); err != nil {
			return PutResult{}, err
		}
	}
	prior, exists := store.objects[request.Key]
	if request.Condition.IfNoneMatch && exists {
		return PutResult{}, ErrPreconditionFailed
	}
	if request.Condition.IfMatch != "" && (!exists || prior.etag != request.Condition.IfMatch) {
		return PutResult{}, ErrPreconditionFailed
	}
	if request.ContentMD5 != digestMD5(request.Body) {
		return PutResult{}, errors.New("bad content MD5")
	}
	etag := fmt.Sprintf("\"etag-%d\"", len(store.puts))
	store.objects[request.Key] = memoryObject{body: append([]byte(nil), request.Body...), request: request, etag: etag}
	return PutResult{ETag: etag}, nil
}

func (store *memoryStore) HeadObject(_ context.Context, key string) (Metadata, error) {
	store.reads = append(store.reads, "head:"+key)
	object, ok := store.objects[key]
	if !ok {
		return Metadata{}, ErrNotFound
	}
	metadata := store.metadata(object)
	if store.mutateHead != nil {
		store.mutateHead(&metadata)
	}
	return metadata, nil
}

func (store *memoryStore) GetObject(_ context.Context, request GetRequest) (GetResult, error) {
	object, ok := store.objects[request.Key]
	if !ok {
		return GetResult{}, ErrNotFound
	}
	result := GetResult{Metadata: store.metadata(object), Body: append([]byte(nil), object.body...)}
	if request.Range == "" {
		store.reads = append(store.reads, "get:"+request.Key)
		if store.mutateGet != nil {
			store.mutateGet(&result)
		}
		return result, nil
	}
	store.reads = append(store.reads, "range:"+request.Key)
	result.Body = append([]byte(nil), object.body[:1]...)
	result.ContentRange = fmt.Sprintf("bytes 0-0/%d", len(object.body))
	if store.mutateRange != nil {
		store.mutateRange(&result)
	}
	return result, nil
}

func (store *memoryStore) metadata(object memoryObject) Metadata {
	return Metadata{
		ETag: object.etag, Length: int64(len(object.body)), SHA256: object.request.SHA256,
		ContentType: object.request.ContentType, CacheControl: object.request.CacheControl,
		ContentEncoding: object.request.ContentEncoding, AcceptRanges: "bytes",
	}
}

func digestHex(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func digestMD5(content []byte) string {
	sum := md5.Sum(content)
	return base64.StdEncoding.EncodeToString(sum[:])
}
