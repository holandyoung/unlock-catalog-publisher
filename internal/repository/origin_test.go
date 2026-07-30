package repository

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRawOriginMatchesProtectedReleaseTree(t *testing.T) {
	repositoryRoot := t.TempDir()
	release := testRelease("catalog-test-data", "manifest", "root", "object")
	if _, err := MaterializeRelease(repositoryRoot, release); err != nil {
		t.Fatal(err)
	}
	prefixRoot := filepath.Join(repositoryRoot, filepath.FromSlash(ReleasePrefix))
	server := httptest.NewTLSServer(http.FileServer(http.Dir(prefixRoot)))
	defer server.Close()

	report, err := VerifyOrigin(context.Background(), OriginOptions{
		RepositoryRoot: repositoryRoot,
		BaseURL:        server.URL + "/",
		Client:         server.Client(),
	})
	if err != nil {
		t.Fatalf("VerifyOrigin: %v", err)
	}
	if report.SourceCount != 1 || report.FileCount != len(release.Files) || report.FileBytes == 0 {
		t.Fatalf("origin report = %+v", report)
	}
}

func TestRawOriginFailsClosedOnTransportAndByteDrift(t *testing.T) {
	repositoryRoot := t.TempDir()
	release := testRelease("catalog-test-data", "manifest", "root", "object")
	if _, err := MaterializeRelease(repositoryRoot, release); err != nil {
		t.Fatal(err)
	}
	prefixRoot := filepath.Join(repositoryRoot, filepath.FromSlash(ReleasePrefix))
	files := http.FileServer(http.Dir(prefixRoot))

	tests := map[string]func(http.ResponseWriter, *http.Request) bool{
		"stale manifest": func(writer http.ResponseWriter, request *http.Request) bool {
			if strings.HasSuffix(request.URL.Path, "/manifest.json") {
				_, _ = writer.Write([]byte("stale"))
				return true
			}
			return false
		},
		"missing object": func(writer http.ResponseWriter, request *http.Request) bool {
			if strings.Contains(request.URL.Path, "/objects/") {
				http.NotFound(writer, request)
				return true
			}
			return false
		},
		"root mismatch": func(writer http.ResponseWriter, request *http.Request) bool {
			if strings.HasSuffix(request.URL.Path, "/root.json") {
				_, _ = writer.Write([]byte("wrong root"))
				return true
			}
			return false
		},
		"package mismatch": func(writer http.ResponseWriter, request *http.Request) bool {
			if strings.Contains(request.URL.Path, "/packages/") {
				_, _ = writer.Write([]byte("wrong package"))
				return true
			}
			return false
		},
		"redirect": func(writer http.ResponseWriter, request *http.Request) bool {
			http.Redirect(writer, request, "/other-origin", http.StatusFound)
			return true
		},
		"cross-origin redirect": func(writer http.ResponseWriter, request *http.Request) bool {
			http.Redirect(writer, request, "https://example.com/other-origin", http.StatusFound)
			return true
		},
		"encoding drift": func(writer http.ResponseWriter, _ *http.Request) bool {
			writer.Header().Set("Content-Encoding", "gzip")
			_, _ = writer.Write([]byte("encoded"))
			return true
		},
		"timeout": func(writer http.ResponseWriter, _ *http.Request) bool {
			time.Sleep(50 * time.Millisecond)
			_, _ = writer.Write([]byte("late"))
			return true
		},
	}
	for name, intercept := range tests {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if !intercept(writer, request) {
					files.ServeHTTP(writer, request)
				}
			}))
			defer server.Close()
			client := server.Client()
			if name == "timeout" {
				client.Timeout = 10 * time.Millisecond
			}
			if _, err := VerifyOrigin(context.Background(), OriginOptions{
				RepositoryRoot: repositoryRoot,
				BaseURL:        server.URL + "/",
				Client:         client,
			}); err == nil {
				t.Fatal("VerifyOrigin reported a mismatched origin as current")
			}
		})
	}
}

func TestRawOriginRejectsHTTPAndNonCanonicalBaseURLs(t *testing.T) {
	repositoryRoot := t.TempDir()
	readme := filepath.Join(repositoryRoot, filepath.FromSlash(ReleasePrefix), "README.md")
	if err := os.MkdirAll(filepath.Dir(readme), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(readme, []byte("sentinel"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, baseURL := range []string{
		"http://example.com/catalog/sources/",
		"https://user@example.com/catalog/sources/",
		"https://example.com/catalog/sources",
		"https://example.com/catalog/sources/?token=secret",
		"https://example.com/catalog/sources/#fragment",
	} {
		t.Run(fmt.Sprintf("%x", baseURL), func(t *testing.T) {
			if _, err := VerifyOrigin(context.Background(), OriginOptions{
				RepositoryRoot: repositoryRoot,
				BaseURL:        baseURL,
				Client:         http.DefaultClient,
			}); err == nil {
				t.Fatalf("VerifyOrigin accepted base URL %q", baseURL)
			}
		})
	}
}
