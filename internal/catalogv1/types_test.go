package catalogv1

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const minimalSourceYAML = `schemaVersion: 1
sourceId: unlock-official-linux-amd64-static
version: 1
validForSeconds: 1209600
minCoreProtocol: 1
maxCoreProtocol: 2
minCoreVersion: 1.0.0
maxCoreVersion: 2.0.0
compatibilityEpoch: 1
permissions:
  - metadata
  - detection-data
  - routing-data
cohort:
  os: linux
  arch: amd64
  abi: static
entries: []
artifacts: []
revocations: []
`

func TestDecodeSourceIsStrict(t *testing.T) {
	if _, err := DecodeSource(strings.NewReader(minimalSourceYAML)); err != nil {
		t.Fatalf("valid source: %v", err)
	}

	for name, mutate := range map[string]func(string) string{
		"unknown field": func(input string) string {
			return input + "credential: forbidden\n"
		},
		"unknown nested field": func(input string) string {
			return strings.Replace(input, "  abi: static", "  abi: static\n  runtime: forbidden", 1)
		},
		"duplicate field": func(input string) string {
			return input + "sourceId: duplicate\n"
		},
		"non-canonical case": func(input string) string {
			return strings.Replace(input, "sourceId:", "SOURCEID:", 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeSource(strings.NewReader(mutate(minimalSourceYAML))); err == nil {
				t.Fatal("invalid source was accepted")
			}
		})
	}
}

func TestCanonicalManifestOrdersStableIDs(t *testing.T) {
	published := time.Unix(1_785_312_000, 0).UTC()
	base := Manifest{
		SchemaVersion: 1,
		Protocol:      ProtocolV1,
		SourceID:      "unlock-official-linux-amd64-static",
		Version:       1,
		PublishedAt:   published,
		ExpiresAt:     published.Add(14 * 24 * time.Hour),
		Entries: []Entry{
			{EntryID: "zulu", Tags: []string{"video", "streaming"}},
			{EntryID: "alpha", Tags: []string{"streaming", "availability"}},
		},
		Artifacts: []ArtifactDescriptor{
			{ArtifactID: "zulu-object"},
			{ArtifactID: "alpha-object"},
		},
		Revocations: []Revocation{
			{RevocationID: "zulu-revocation"},
			{RevocationID: "alpha-revocation"},
		},
	}

	first, err := CanonicalManifest(base)
	if err != nil {
		t.Fatal(err)
	}
	base.Entries[0], base.Entries[1] = base.Entries[1], base.Entries[0]
	base.Artifacts[0], base.Artifacts[1] = base.Artifacts[1], base.Artifacts[0]
	base.Revocations[0], base.Revocations[1] = base.Revocations[1], base.Revocations[0]
	second, err := CanonicalManifest(base)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("canonical bytes depend on input order\nfirst:  %s\nsecond: %s", first, second)
	}
	if bytes.ContainsAny(first, "\n\t") {
		t.Fatalf("canonical payload contains insignificant whitespace: %q", first)
	}
	if strings.Index(string(first), `"entryId":"alpha"`) > strings.Index(string(first), `"entryId":"zulu"`) {
		t.Fatalf("entries are not ordered by stable ID: %s", first)
	}
}

func TestCheckedInvalidSourceFixturesAreRejected(t *testing.T) {
	fixtures, err := filepath.Glob(filepath.Join("..", "..", "fixtures", "v1", "candidate", "invalid", "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(fixtures) == 0 {
		t.Fatal("no checked invalid source fixtures")
	}
	for _, fixture := range fixtures {
		t.Run(filepath.Base(fixture), func(t *testing.T) {
			file, err := os.Open(fixture)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			if _, err := DecodeSource(file); err == nil {
				t.Fatal("invalid source fixture was accepted")
			}
		})
	}
}
