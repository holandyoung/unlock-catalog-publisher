// Package repository publishes assembled Catalog releases through conditional
// object-store operations.
package repository

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"strings"
)

const (
	ImmutableCacheControl = "public, max-age=31536000, immutable"
	LiveCacheControl      = "no-cache, max-age=0, must-revalidate"
)

var (
	ErrPreconditionFailed = errors.New("object-store precondition failed")
	ErrNotFound           = errors.New("object not found")
	ErrImmutableCollision = errors.New("immutable object collision")
	ErrReadbackMismatch   = errors.New("object readback mismatch")
	ErrLostUpdate         = errors.New("live pointer lost update")
)

type Object struct {
	Key         string
	Body        []byte
	ContentType string
}

type PutCondition struct {
	IfNoneMatch bool
	IfMatch     string
}

type PutRequest struct {
	Object
	CacheControl    string
	ContentEncoding string
	SHA256          string
	ContentMD5      string
	Condition       PutCondition
}

type PutResult struct {
	ETag string
}

type Metadata struct {
	ETag            string
	Length          int64
	SHA256          string
	ContentType     string
	CacheControl    string
	ContentEncoding string
	AcceptRanges    string
}

type GetRequest struct {
	Key   string
	Range string
}

type GetResult struct {
	Metadata
	Body         []byte
	ContentRange string
}

type StoredObject struct {
	Key    string
	ETag   string
	SHA256 string
	Length int64
}

type ObjectStore interface {
	PutObject(context.Context, PutRequest) (PutResult, error)
	HeadObject(context.Context, string) (Metadata, error)
	GetObject(context.Context, GetRequest) (GetResult, error)
}

func PutImmutable(ctx context.Context, store ObjectStore, object Object) (StoredObject, error) {
	if err := validateObject(object); err != nil {
		return StoredObject{}, err
	}
	request := newPutRequest(object, ImmutableCacheControl)
	request.Condition.IfNoneMatch = true
	result, err := store.PutObject(ctx, request)
	if err != nil {
		if !errors.Is(err, ErrPreconditionFailed) {
			return StoredObject{}, fmt.Errorf("create immutable object %q: %w", object.Key, err)
		}
		stored, verifyErr := verifyRemoteObject(ctx, store, object, "")
		if verifyErr != nil {
			return StoredObject{}, fmt.Errorf("%w %q: %v", ErrImmutableCollision, object.Key, verifyErr)
		}
		return stored, nil
	}
	if result.ETag == "" {
		return StoredObject{}, fmt.Errorf("%w %q: put response omitted ETag", ErrReadbackMismatch, object.Key)
	}
	stored, err := verifyRemoteObject(ctx, store, object, result.ETag)
	if err != nil {
		return StoredObject{}, err
	}
	return stored, nil
}

func CompareAndSwapLive(ctx context.Context, store ObjectStore, object Object, expectedETag *string) (StoredObject, error) {
	if err := validateObject(object); err != nil {
		return StoredObject{}, err
	}
	request := newPutRequest(object, LiveCacheControl)
	if expectedETag == nil {
		request.Condition.IfNoneMatch = true
	} else {
		if *expectedETag == "" {
			return StoredObject{}, fmt.Errorf("expected live ETag is empty")
		}
		request.Condition.IfMatch = *expectedETag
	}
	result, err := store.PutObject(ctx, request)
	if err != nil {
		if errors.Is(err, ErrPreconditionFailed) {
			return StoredObject{}, fmt.Errorf("%w for %q", ErrLostUpdate, object.Key)
		}
		return StoredObject{}, fmt.Errorf("replace live object %q: %w", object.Key, err)
	}
	if result.ETag == "" {
		return StoredObject{}, fmt.Errorf("live object %q response omitted ETag", object.Key)
	}
	return StoredObject{Key: object.Key, ETag: result.ETag, SHA256: request.SHA256, Length: int64(len(object.Body))}, nil
}

func newPutRequest(object Object, cacheControl string) PutRequest {
	return PutRequest{
		Object: object, CacheControl: cacheControl, SHA256: sha256Hex(object.Body),
		ContentMD5: contentMD5(object.Body),
	}
}

func verifyRemoteObject(ctx context.Context, store ObjectStore, object Object, putETag string) (StoredObject, error) {
	expectedSHA := sha256Hex(object.Body)
	head, err := store.HeadObject(ctx, object.Key)
	if err != nil {
		return StoredObject{}, fmt.Errorf("%w %q HEAD: %v", ErrReadbackMismatch, object.Key, err)
	}
	if err := validateMetadata(head, object, expectedSHA, putETag, int64(len(object.Body)), true); err != nil {
		return StoredObject{}, err
	}
	full, err := store.GetObject(ctx, GetRequest{Key: object.Key})
	if err != nil {
		return StoredObject{}, fmt.Errorf("%w %q GET: %v", ErrReadbackMismatch, object.Key, err)
	}
	if err := validateMetadata(full.Metadata, object, expectedSHA, head.ETag, int64(len(object.Body)), false); err != nil {
		return StoredObject{}, err
	}
	if full.ContentRange != "" || !bytes.Equal(full.Body, object.Body) || sha256Hex(full.Body) != expectedSHA {
		return StoredObject{}, fmt.Errorf("%w %q: full GET bytes differ", ErrReadbackMismatch, object.Key)
	}
	ranged, err := store.GetObject(ctx, GetRequest{Key: object.Key, Range: "bytes=0-0"})
	if err != nil {
		return StoredObject{}, fmt.Errorf("%w %q range GET: %v", ErrReadbackMismatch, object.Key, err)
	}
	if err := validateMetadataHeaders(ranged.Metadata, object, expectedSHA, head.ETag); err != nil {
		return StoredObject{}, err
	}
	wantRange := fmt.Sprintf("bytes 0-0/%d", len(object.Body))
	if ranged.ContentRange != wantRange || len(ranged.Body) != 1 || ranged.Body[0] != object.Body[0] {
		return StoredObject{}, fmt.Errorf("%w %q: byte range differs", ErrReadbackMismatch, object.Key)
	}
	return StoredObject{Key: object.Key, ETag: head.ETag, SHA256: expectedSHA, Length: int64(len(object.Body))}, nil
}

func validateMetadata(metadata Metadata, object Object, expectedSHA, expectedETag string, expectedLength int64, requireRanges bool) error {
	if err := validateMetadataHeaders(metadata, object, expectedSHA, expectedETag); err != nil {
		return err
	}
	if metadata.Length != expectedLength {
		return fmt.Errorf("%w %q: length differs", ErrReadbackMismatch, object.Key)
	}
	if requireRanges && metadata.AcceptRanges != "bytes" {
		return fmt.Errorf("%w %q: byte ranges are unavailable", ErrReadbackMismatch, object.Key)
	}
	return nil
}

func validateMetadataHeaders(metadata Metadata, object Object, expectedSHA, expectedETag string) error {
	if metadata.ETag == "" || (expectedETag != "" && metadata.ETag != expectedETag) {
		return fmt.Errorf("%w %q: ETag differs", ErrReadbackMismatch, object.Key)
	}
	if metadata.SHA256 != expectedSHA {
		return fmt.Errorf("%w %q: SHA256 metadata differs", ErrReadbackMismatch, object.Key)
	}
	if metadata.ContentType != object.ContentType || metadata.CacheControl != ImmutableCacheControl {
		return fmt.Errorf("%w %q: HTTP metadata differs", ErrReadbackMismatch, object.Key)
	}
	if metadata.ContentEncoding != "" {
		return fmt.Errorf("%w %q: content encoding is not identity", ErrReadbackMismatch, object.Key)
	}
	return nil
}

func validateObject(object Object) error {
	if object.Key == "" || path.IsAbs(object.Key) || path.Clean(object.Key) != object.Key ||
		object.Key == "." || strings.HasPrefix(object.Key, "../") || strings.Contains(object.Key, "\\") {
		return fmt.Errorf("unsafe object key %q", object.Key)
	}
	if len(object.Body) == 0 {
		return fmt.Errorf("object %q is empty", object.Key)
	}
	if object.ContentType == "" {
		return fmt.Errorf("object %q content type is required", object.Key)
	}
	return nil
}

func sha256Hex(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func contentMD5(content []byte) string {
	sum := md5.Sum(content)
	return base64.StdEncoding.EncodeToString(sum[:])
}
