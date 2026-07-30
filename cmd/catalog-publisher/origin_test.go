package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRawOriginCommandVerifiesAnonymousStableBaseURL(t *testing.T) {
	repositoryRoot := t.TempDir()
	prefixRoot := filepath.Join(repositoryRoot, "catalog", "sources")
	if err := os.MkdirAll(prefixRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(prefixRoot, "README.md"), []byte("raw origin sentinel"), 0o644); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.FileServer(http.Dir(prefixRoot)))
	defer server.Close()
	prior := http.DefaultClient
	http.DefaultClient = server.Client()
	defer func() { http.DefaultClient = prior }()

	var stdout, stderr bytes.Buffer
	if err := run([]string{"verify-origin", "--repository", repositoryRoot, "--base-url", server.URL + "/"},
		func(string) string { return "" }, &stdout, &stderr); err != nil {
		t.Fatalf("verify-origin: %v", err)
	}
	if !strings.Contains(stdout.String(), `"sourceCount":0`) || !strings.Contains(stdout.String(), `"fileCount":1`) {
		t.Fatalf("origin report = %q", stdout.String())
	}
}

func TestRawOriginCommandRejectsCredentialFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"verify-origin", "--base-url", "https://example.com/catalog/sources/", "--token", "forbidden"},
		func(string) string { return "" }, &stdout, &stderr)
	if err == nil || stdout.Len() != 0 {
		t.Fatalf("credential-bearing command accepted: err=%v stdout=%q", err, stdout.String())
	}
}
