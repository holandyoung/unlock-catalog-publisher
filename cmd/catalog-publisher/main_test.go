package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestDeployCommandValidatesTargetAndCASBeforeCredentials(t *testing.T) {
	release := filepath.Join("..", "..", "fixtures", "v1", "signed", "positive", "data", "release")
	for name, args := range map[string][]string{
		"both CAS modes": {"deploy", "--target", "manifest", "--release", release, "--initial-live", "--expected-live-etag", "etag"},
		"unknown target": {"deploy", "--target", "sign", "--release", release, "--initial-live"},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			err := run(args, func(string) string { return "" }, &stdout, &stderr)
			if err == nil || strings.Contains(err.Error(), "usage: catalog-publisher candidate") {
				t.Fatalf("deploy command was not independently validated: %v", err)
			}
			if stdout.Len() != 0 {
				t.Fatalf("failed deploy wrote stdout: %q", stdout.String())
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
