package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/holandyoung/unlock-catalog/internal/policy"
	"github.com/holandyoung/unlock-catalog/internal/signing"
)

func TestSourceDateEpochIsRequiredAndStrict(t *testing.T) {
	for name, value := range map[string]string{
		"missing":    "",
		"not base10": "0x10",
		"negative":   "-1",
		"fraction":   "1785312000.5",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := sourceDateEpoch(func(string) string { return value }); err == nil {
				t.Fatal("invalid SOURCE_DATE_EPOCH was accepted")
			}
		})
	}

	got, err := sourceDateEpoch(func(string) string { return "1785312000" })
	if err != nil {
		t.Fatal(err)
	}
	want := time.Unix(1_785_312_000, 0).UTC()
	if !got.Equal(want) || got.Location() != time.UTC {
		t.Fatalf("epoch = %s want %s UTC", got, want)
	}
}

func TestCandidateCommandProducesSignerCompatibleDirectories(t *testing.T) {
	output := filepath.Join(t.TempDir(), "candidate")
	var stdout, stderr bytes.Buffer
	err := run(
		[]string{"candidate", "--sources", filepath.Join("..", "..", "catalog", "definitions"), "--output", output},
		func(name string) string {
			if name == "SOURCE_DATE_EPOCH" {
				return "1785312000"
			}
			return ""
		},
		&stdout,
		&stderr,
	)
	if err != nil {
		t.Fatalf("build candidate set: %v", err)
	}
	assertDirectoryMode(t, output, 0o755)
	for _, sourceID := range []string{policy.DataSourceID, policy.ExecSourceID} {
		candidate := filepath.Join(output, sourceID)
		if _, err := signing.Inspect(candidate); err != nil {
			t.Fatalf("inspect published candidate %q: %v", sourceID, err)
		}
	}
}

func assertDirectoryMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() || info.Mode().Perm() != want {
		t.Fatalf("directory %s mode = %04o want %04o", path, info.Mode().Perm(), want)
	}
}

func TestMaterializeCommandValidatesInputsWithoutCredentials(t *testing.T) {
	release := filepath.Join("..", "..", "fixtures", "v1", "signed", "positive", "data", "release")
	for name, args := range map[string][]string{
		"missing release": {"materialize", "--repository", t.TempDir()},
		"unknown flag":    {"materialize", "--release", release, "--credential", "forbidden"},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			err := run(args, func(string) string { return "" }, &stdout, &stderr)
			if err == nil || strings.Contains(err.Error(), "usage: catalog-publisher candidate") {
				t.Fatalf("materialize command was not independently validated: %v", err)
			}
			if stdout.Len() != 0 {
				t.Fatalf("failed materialize wrote stdout: %q", stdout.String())
			}
		})
	}
}

func TestRunKeepsCommandBoundaryNarrow(t *testing.T) {
	getenv := func(string) string { return "1785312000" }
	for name, args := range map[string][]string{
		"missing command": nil,
		"unknown command": {"sign"},
		"missing output":  {"candidate"},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := run(args, getenv, &stdout, &stderr); err == nil {
				t.Fatal("invalid command was accepted")
			}
			if stdout.Len() != 0 {
				t.Fatalf("failed command wrote stdout: %q", stdout.String())
			}
		})
	}
}
