package main

import (
	"bytes"
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
