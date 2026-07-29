package packagefile

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBuildAndVerifyPackageRejectUnsafeTreesAndArchives(t *testing.T) {
	root := t.TempDir()
	files := map[string][]byte{
		"manifest.json":                      []byte(`{"signed":{}}`),
		"root.json":                          []byte(`{"signed":{}}`),
		"objects/sha256/aa/aaaaaaaaaaaaaaaa": []byte("object"),
	}
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	output := filepath.Join(t.TempDir(), "release.ucp")
	if err := BuildPackage(root, output, files); err != nil {
		t.Fatalf("BuildPackage: %v", err)
	}
	if err := VerifyPackage(output, files); err != nil {
		t.Fatalf("VerifyPackage: %v", err)
	}

	if err := os.WriteFile(filepath.Join(root, "extra.txt"), []byte("extra"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := BuildPackage(root, filepath.Join(t.TempDir(), "extra.ucp"), files); err == nil {
		t.Fatal("BuildPackage accepted an extra file")
	}

	for name, testCase := range map[string]struct {
		entries []zipEntry
		want    string
	}{
		"traversal": {append(zipEntries(files), zipEntry{name: "../escape", content: []byte("escape")}), "unsafe package path"},
		"duplicate": {append(zipEntries(files), zipEntry{name: "manifest.json", content: files["manifest.json"]}), "duplicate file"},
		"extra":     {append(zipEntries(files), zipEntry{name: "extra.txt", content: []byte("extra")}), "extra file"},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), name+".ucp")
			writeZIP(t, path, testCase.entries)
			if err := VerifyPackage(path, files); err == nil {
				t.Fatal("VerifyPackage accepted unsafe archive")
			} else if !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("VerifyPackage error = %q, want %q", err, testCase.want)
			}
		})
	}
}

type zipEntry struct {
	name    string
	content []byte
}

func zipEntries(files map[string][]byte) []zipEntry {
	entries := make([]zipEntry, 0, len(files))
	for name, content := range files {
		entries = append(entries, zipEntry{name: name, content: content})
	}
	return entries
}

func writeZIP(t *testing.T, path string, entries []zipEntry) {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.name, Method: zip.Store}
		header.SetMode(0o644)
		header.SetModTime(time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC))
		file, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(entry.content); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buffer.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}
