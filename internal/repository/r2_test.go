package repository

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestR2AdapterSendsConditionalIntegrityHeadersAndReadsMetadata(t *testing.T) {
	body := []byte("immutable")
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/test-bucket/v1/source/object.json" {
			t.Errorf("request path = %q", request.URL.Path)
		}
		if request.Header.Get("Accept-Encoding") != "identity" {
			t.Errorf("Accept-Encoding = %q", request.Header.Get("Accept-Encoding"))
		}
		switch request.Method {
		case http.MethodPut:
			content, err := io.ReadAll(request.Body)
			if err != nil {
				t.Error(err)
			}
			if string(content) != string(body) {
				t.Errorf("PUT body = %q", content)
			}
			if request.Header.Get("If-None-Match") != "*" || request.Header.Get("If-Match") != "" {
				t.Errorf("conditional headers = %v", request.Header)
			}
			if request.Header.Get("Content-MD5") != digestMD5(body) ||
				request.Header.Get("X-Amz-Meta-Sha256") != digestHex(body) {
				t.Errorf("integrity headers = %v", request.Header)
			}
			if request.Header.Get("X-Amz-Checksum-Crc32") != "" {
				t.Errorf("unsupported SDK checksum was added: %v", request.Header)
			}
			response.Header().Set("ETag", "\"put-etag\"")
		case http.MethodHead:
			writeObjectHeaders(response, body)
		case http.MethodGet:
			writeObjectHeaders(response, body)
			if request.Header.Get("Range") == "bytes=0-0" {
				response.Header().Set("Content-Range", "bytes 0-0/9")
				response.Header().Set("Content-Length", "1")
				response.WriteHeader(http.StatusPartialContent)
				_, _ = response.Write(body[:1])
				return
			}
			_, _ = response.Write(body)
		default:
			t.Errorf("unexpected method %s", request.Method)
			response.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	store, err := NewR2Store(context.Background(), R2Config{
		Endpoint: server.URL, Bucket: "test-bucket",
		AccessKeyID: "TESTONLYACCESS", SecretAccessKey: "TESTONLYSECRET",
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("NewR2Store: %v", err)
	}
	request := PutRequest{
		Object:       Object{Key: "v1/source/object.json", Body: body, ContentType: "application/json"},
		CacheControl: ImmutableCacheControl, SHA256: digestHex(body), ContentMD5: digestMD5(body),
		Condition: PutCondition{IfNoneMatch: true},
	}
	if result, err := store.PutObject(context.Background(), request); err != nil || result.ETag != "\"put-etag\"" {
		t.Fatalf("PutObject result=%+v err=%v", result, err)
	}
	head, err := store.HeadObject(context.Background(), request.Key)
	if err != nil {
		t.Fatalf("HeadObject: %v", err)
	}
	if head.ETag != "\"stored-etag\"" || head.SHA256 != digestHex(body) || head.AcceptRanges != "bytes" {
		t.Fatalf("HEAD metadata = %+v", head)
	}
	full, err := store.GetObject(context.Background(), GetRequest{Key: request.Key})
	if err != nil || string(full.Body) != string(body) || full.ContentRange != "" {
		t.Fatalf("full GET result=%+v err=%v", full, err)
	}
	ranged, err := store.GetObject(context.Background(), GetRequest{Key: request.Key, Range: "bytes=0-0"})
	if err != nil || string(ranged.Body) != "i" || ranged.ContentRange != "bytes 0-0/9" {
		t.Fatalf("range GET result=%+v err=%v", ranged, err)
	}
}

func TestR2AdapterMapsPreconditionAndNotFound(t *testing.T) {
	for name, status := range map[string]int{"precondition": http.StatusPreconditionFailed, "not found": http.StatusNotFound} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				response.Header().Set("Content-Type", "application/xml")
				code := "NoSuchKey"
				if status == http.StatusPreconditionFailed {
					code = "PreconditionFailed"
				}
				response.WriteHeader(status)
				_, _ = response.Write([]byte("<Error><Code>" + code + "</Code><Message>test only</Message></Error>"))
			}))
			defer server.Close()
			store, err := NewR2Store(context.Background(), R2Config{
				Endpoint: server.URL, Bucket: "test-bucket",
				AccessKeyID: "TESTONLYACCESS", SecretAccessKey: "TESTONLYSECRET",
				HTTPClient: server.Client(),
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = store.PutObject(context.Background(), PutRequest{
				Object:       Object{Key: "v1/source/object", Body: []byte("x"), ContentType: "text/plain"},
				CacheControl: ImmutableCacheControl, SHA256: strings.Repeat("0", 64),
				ContentMD5: digestMD5([]byte("x")), Condition: PutCondition{IfNoneMatch: true},
			})
			if status == http.StatusPreconditionFailed && !errorsIs(err, ErrPreconditionFailed) {
				t.Fatalf("precondition error = %v", err)
			}
			if status == http.StatusNotFound && !errorsIs(err, ErrNotFound) {
				t.Fatalf("not found error = %v", err)
			}
		})
	}
}

func TestR2ConfigRejectsUnsafeEndpointAndMissingAuthority(t *testing.T) {
	tests := []R2Config{
		{Endpoint: "http://example.test", Bucket: "test-bucket", AccessKeyID: "TESTONLYACCESS", SecretAccessKey: "TESTONLYSECRET"},
		{Endpoint: "https://example.test/path", Bucket: "test-bucket", AccessKeyID: "TESTONLYACCESS", SecretAccessKey: "TESTONLYSECRET"},
		{Endpoint: "https://example.test", Bucket: "", AccessKeyID: "TESTONLYACCESS", SecretAccessKey: "TESTONLYSECRET"},
		{Endpoint: "https://example.test", Bucket: "test-bucket", AccessKeyID: "", SecretAccessKey: ""},
	}
	for _, config := range tests {
		if _, err := NewR2Store(context.Background(), config); err == nil {
			t.Fatalf("unsafe R2 config accepted: endpoint=%q bucket=%q", config.Endpoint, config.Bucket)
		}
	}
}

func writeObjectHeaders(response http.ResponseWriter, body []byte) {
	response.Header().Set("ETag", "\"stored-etag\"")
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", ImmutableCacheControl)
	response.Header().Set("Accept-Ranges", "bytes")
	response.Header().Set("X-Amz-Meta-Sha256", digestHex(body))
	response.Header().Set("Content-Length", "9")
}

func errorsIs(err, target error) bool {
	for err != nil {
		if err == target {
			return true
		}
		type unwrapper interface{ Unwrap() error }
		wrapped, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = wrapped.Unwrap()
	}
	return false
}
