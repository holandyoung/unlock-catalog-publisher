package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRejectsUnknownAndIncompleteCommands(t *testing.T) {
	for name, args := range map[string][]string{
		"missing command":    nil,
		"unknown command":    {"sign"},
		"incomplete root":    {"root", "--current-root", "root.json"},
		"incomplete release": {"release", "--candidate", "candidate"},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := run(args, &stdout, &stderr); err == nil {
				t.Fatal("run accepted invalid command")
			}
			if strings.Contains(stdout.String(), "PRIVATE") || strings.Contains(stderr.String(), "PRIVATE") {
				t.Fatal("command output exposed signing material")
			}
		})
	}
}

func TestDecodeFileRejectsTrailingJSONData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "root.json")
	if err := os.WriteFile(path, []byte(`{"version":1}]`), 0o644); err != nil {
		t.Fatal(err)
	}
	var target struct {
		Version int `json:"version"`
	}
	if err := decodeFile(path, &target); err == nil {
		t.Fatal("decodeFile accepted trailing JSON data")
	}
}
