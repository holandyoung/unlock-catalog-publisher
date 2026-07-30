package packagefile

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
)

func TestPackageDeterministicTarZstdContract(t *testing.T) {
	options := testBuildOptions(t)
	first := filepath.Join(t.TempDir(), PackageFileName)
	second := filepath.Join(t.TempDir(), PackageFileName)
	firstOptions := options
	firstOptions.Output = first
	secondOptions := options
	secondOptions.Output = second

	if err := BuildPackage(firstOptions); err != nil {
		t.Fatalf("first BuildPackage: %v", err)
	}
	if err := BuildPackage(secondOptions); err != nil {
		t.Fatalf("second BuildPackage: %v", err)
	}
	firstBytes := mustReadFile(t, first)
	secondBytes := mustReadFile(t, second)
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("independent package builds differ")
	}
	if len(firstBytes) < 4 || !bytes.Equal(firstBytes[:4], []byte{0x28, 0xb5, 0x2f, 0xfd}) {
		t.Fatal("package is not a zstd frame")
	}
	if err := VerifyPackage(first, verifyOptions(options)); err != nil {
		t.Fatalf("VerifyPackage: %v", err)
	}

	entries := readPackageEntries(t, firstBytes)
	repacked := filepath.Join(t.TempDir(), PackageFileName)
	writePackageEntries(t, repacked, cloneTarEntries(entries), false)
	if err := VerifyPackage(repacked, verifyOptions(options)); err != nil {
		t.Fatalf("verify unpack/repack round-trip: %v", err)
	}
	if !bytes.Equal(firstBytes, mustReadFile(t, repacked)) {
		t.Fatal("unpack/repack changed canonical package bytes")
	}
	wantNames := []string{"package.json"}
	for name := range options.Files {
		wantNames = append(wantNames, "repository/"+name)
	}
	sort.Strings(wantNames[1:])
	if got := entryNames(entries); !equalStrings(got, wantNames) {
		t.Fatalf("package members = %v, want %v", got, wantNames)
	}
	for _, entry := range entries {
		if entry.header.Format != tar.FormatUSTAR || entry.header.Mode != 0o644 || entry.header.Uid != 0 ||
			entry.header.Gid != 0 || !entry.header.ModTime.Equal(time.Unix(0, 0).UTC()) ||
			entry.header.Typeflag != tar.TypeReg {
			t.Fatalf("non-canonical header for %q: %+v", entry.header.Name, entry.header)
		}
	}
	var metadata PackageMetadata
	if err := json.Unmarshal(entries[0].body, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.Format != PackageFormat || metadata.SourceID != options.SourceID ||
		metadata.ManifestDigest != options.ManifestDigest ||
		metadata.ManifestEnvelopeSHA256 != options.ManifestEnvelopeSHA256 ||
		metadata.RootVersion == nil || *metadata.RootVersion != *options.RootVersion {
		t.Fatalf("package metadata = %+v", metadata)
	}
	if bytes.Contains(entries[0].body, []byte(PackageFileName)) {
		t.Fatal("package metadata contains a package self-reference")
	}
}

func TestPackageRejectsUnsafeInputTree(t *testing.T) {
	tests := map[string]func(*testing.T, *BuildOptions){
		"extra file": func(t *testing.T, options *BuildOptions) {
			writeTestFile(t, options.Root, "extra.txt", []byte("extra"))
		},
		"symlink": func(t *testing.T, options *BuildOptions) {
			manifest := filepath.Join(options.Root, "manifest.json")
			if err := os.Remove(manifest); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("root.json", manifest); err != nil {
				t.Fatal(err)
			}
		},
		"mode drift": func(t *testing.T, options *BuildOptions) {
			if err := os.Chmod(filepath.Join(options.Root, "manifest.json"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"repository prefix": func(t *testing.T, options *BuildOptions) {
			options.Files["repository/manifest.json"] = options.Files["manifest.json"]
			delete(options.Files, "manifest.json")
		},
		"object path digest": func(t *testing.T, options *BuildOptions) {
			for name := range options.Files {
				if strings.HasPrefix(name, "objects/") {
					options.Files[name] = []byte("different object")
					writeTestFile(t, options.Root, name, options.Files[name])
					return
				}
			}
			t.Fatal("test package has no object")
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			options := testBuildOptions(t)
			options.Output = filepath.Join(t.TempDir(), PackageFileName)
			mutate(t, &options)
			if err := BuildPackage(options); err == nil {
				t.Fatal("BuildPackage accepted unsafe input")
			}
		})
	}

	options := testBuildOptions(t)
	options.Output = filepath.Join(t.TempDir(), "legacy.ucp")
	if err := BuildPackage(options); err == nil {
		t.Fatal("BuildPackage accepted a non-canonical package filename")
	}
}

func TestPackageRejectsArchiveAndMetadataDrift(t *testing.T) {
	options := testBuildOptions(t)
	validPath := filepath.Join(t.TempDir(), PackageFileName)
	options.Output = validPath
	if err := BuildPackage(options); err != nil {
		t.Fatal(err)
	}
	valid := readPackageEntries(t, mustReadFile(t, validPath))

	tests := map[string]func([]testTarEntry) []testTarEntry{
		"traversal": func(entries []testTarEntry) []testTarEntry {
			entries[1].header.Name = "../escape"
			return entries
		},
		"backslash": func(entries []testTarEntry) []testTarEntry {
			entries[1].header.Name = `repository\\manifest.json`
			return entries
		},
		"duplicate member": func(entries []testTarEntry) []testTarEntry {
			return append(entries, cloneTarEntry(entries[1]))
		},
		"case collision": func(entries []testTarEntry) []testTarEntry {
			entry := cloneTarEntry(entries[1])
			entry.header.Name = strings.ToUpper(entry.header.Name)
			return append(entries, entry)
		},
		"symlink": func(entries []testTarEntry) []testTarEntry {
			entries[1].header.Typeflag = tar.TypeSymlink
			entries[1].header.Linkname = "repository/root.json"
			entries[1].body = nil
			entries[1].header.Size = 0
			return entries
		},
		"hardlink": func(entries []testTarEntry) []testTarEntry {
			entries[1].header.Typeflag = tar.TypeLink
			entries[1].header.Linkname = "repository/root.json"
			entries[1].body = nil
			entries[1].header.Size = 0
			return entries
		},
		"device": func(entries []testTarEntry) []testTarEntry {
			entries[1].header.Typeflag = tar.TypeBlock
			entries[1].body = nil
			entries[1].header.Size = 0
			return entries
		},
		"fifo": func(entries []testTarEntry) []testTarEntry {
			entries[1].header.Typeflag = tar.TypeFifo
			entries[1].body = nil
			entries[1].header.Size = 0
			return entries
		},
		"mode": func(entries []testTarEntry) []testTarEntry {
			entries[1].header.Mode = 0o600
			return entries
		},
		"uid": func(entries []testTarEntry) []testTarEntry {
			entries[1].header.Uid = 1
			return entries
		},
		"gid": func(entries []testTarEntry) []testTarEntry {
			entries[1].header.Gid = 1
			return entries
		},
		"mtime": func(entries []testTarEntry) []testTarEntry {
			entries[1].header.ModTime = time.Unix(1, 0).UTC()
			return entries
		},
		"gnu": func(entries []testTarEntry) []testTarEntry {
			entries[1].header.Format = tar.FormatGNU
			return entries
		},
		"pax": func(entries []testTarEntry) []testTarEntry {
			entries[1].header.Format = tar.FormatPAX
			entries[1].header.PAXRecords = map[string]string{"comment": "non-canonical extension"}
			return entries
		},
		"missing member": func(entries []testTarEntry) []testTarEntry {
			return entries[:len(entries)-1]
		},
		"extra member": func(entries []testTarEntry) []testTarEntry {
			extra := cloneTarEntry(entries[1])
			extra.header.Name = "repository/extra.txt"
			extra.body = []byte("extra")
			extra.header.Size = int64(len(extra.body))
			return append(entries, extra)
		},
		"metadata digest": func(entries []testTarEntry) []testTarEntry {
			mutateMetadata(t, &entries[0], func(metadata *PackageMetadata) { metadata.Files[0].SHA256 = strings.Repeat("0", 64) })
			return entries
		},
		"metadata length": func(entries []testTarEntry) []testTarEntry {
			mutateMetadata(t, &entries[0], func(metadata *PackageMetadata) { metadata.Files[0].Length++ })
			return entries
		},
		"metadata unsorted": func(entries []testTarEntry) []testTarEntry {
			mutateMetadata(t, &entries[0], func(metadata *PackageMetadata) {
				metadata.Files[0], metadata.Files[1] = metadata.Files[1], metadata.Files[0]
			})
			return entries
		},
		"metadata duplicate": func(entries []testTarEntry) []testTarEntry {
			mutateMetadata(t, &entries[0], func(metadata *PackageMetadata) { metadata.Files = append(metadata.Files, metadata.Files[0]) })
			return entries
		},
		"metadata self hash": func(entries []testTarEntry) []testTarEntry {
			mutateMetadata(t, &entries[0], func(metadata *PackageMetadata) {
				metadata.Files = append(metadata.Files, PackageFile{Path: "package.json", Length: 1, SHA256: strings.Repeat("0", 64)})
			})
			return entries
		},
		"metadata prefix drift": func(entries []testTarEntry) []testTarEntry {
			mutateMetadata(t, &entries[0], func(metadata *PackageMetadata) { metadata.Files[0].Path = "manifest.json" })
			return entries
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			entries := cloneTarEntries(valid)
			candidate := filepath.Join(t.TempDir(), PackageFileName)
			writePackageEntries(t, candidate, mutate(entries), false)
			if err := VerifyPackage(candidate, verifyOptions(options)); err == nil {
				t.Fatal("VerifyPackage accepted unsafe archive")
			}
		})
	}

	t.Run("duplicate JSON field", func(t *testing.T) {
		entries := cloneTarEntries(valid)
		entries[0].body = bytes.Replace(entries[0].body, []byte(`{"format":`), []byte(`{"format":"unlock-catalog-package-v1","format":`), 1)
		entries[0].header.Size = int64(len(entries[0].body))
		candidate := filepath.Join(t.TempDir(), PackageFileName)
		writePackageEntries(t, candidate, entries, false)
		if err := VerifyPackage(candidate, verifyOptions(options)); err == nil {
			t.Fatal("VerifyPackage accepted duplicate package.json field")
		}
	})
	t.Run("unknown JSON field", func(t *testing.T) {
		entries := cloneTarEntries(valid)
		entries[0].body = append(entries[0].body[:len(entries[0].body)-1], []byte(`,"unknown":true}`)...)
		entries[0].header.Size = int64(len(entries[0].body))
		candidate := filepath.Join(t.TempDir(), PackageFileName)
		writePackageEntries(t, candidate, entries, false)
		if err := VerifyPackage(candidate, verifyOptions(options)); err == nil {
			t.Fatal("VerifyPackage accepted unknown package.json field")
		}
	})
	t.Run("trailing compressed data", func(t *testing.T) {
		candidate := filepath.Join(t.TempDir(), PackageFileName)
		writePackageEntries(t, candidate, cloneTarEntries(valid), true)
		if err := VerifyPackage(candidate, verifyOptions(options)); err == nil {
			t.Fatal("VerifyPackage accepted trailing compressed data")
		}
	})
	t.Run("trailing tar data", func(t *testing.T) {
		archive := decodePackage(t, mustReadFile(t, validPath))
		archive = append(archive, make([]byte, 512)...)
		candidate := filepath.Join(t.TempDir(), PackageFileName)
		writeCompressedArchive(t, candidate, archive)
		if err := VerifyPackage(candidate, verifyOptions(options)); err == nil {
			t.Fatal("VerifyPackage accepted trailing tar data")
		}
	})
	t.Run("sparse member", func(t *testing.T) {
		archive := decodePackage(t, mustReadFile(t, validPath))
		archive[156] = tar.TypeGNUSparse
		updateTarChecksum(archive[:512])
		candidate := filepath.Join(t.TempDir(), PackageFileName)
		writeCompressedArchive(t, candidate, archive)
		if err := VerifyPackage(candidate, verifyOptions(options)); err == nil {
			t.Fatal("VerifyPackage accepted a sparse member")
		}
	})
}

func TestPackageLimitsFailClosed(t *testing.T) {
	options := testBuildOptions(t)
	options.Output = filepath.Join(t.TempDir(), PackageFileName)
	if err := BuildPackage(options); err != nil {
		t.Fatal(err)
	}
	limits := defaultPackageLimits()

	tests := map[string]func(*packageLimits){
		"compressed":   func(value *packageLimits) { value.maxCompressedBytes = 1 },
		"uncompressed": func(value *packageLimits) { value.maxUncompressedBytes = 1 },
		"member count": func(value *packageLimits) { value.maxMembers = 1 },
		"member bytes": func(value *packageLimits) { value.maxArtifactBytes = 1 },
		"manifest":     func(value *packageLimits) { value.maxManifestBytes = 1 },
		"path":         func(value *packageLimits) { value.maxPathBytes = 1 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := limits
			mutate(&candidate)
			if err := verifyPackage(options.Output, verifyOptions(options), candidate); err == nil {
				t.Fatal("VerifyPackage accepted input over a configured limit")
			}
		})
	}
}

func testBuildOptions(t *testing.T) BuildOptions {
	t.Helper()
	root := t.TempDir()
	object := []byte("immutable catalog object")
	objectDigest := digest(object)
	files := map[string][]byte{
		"manifest.json": []byte(`{"signed":{"sourceId":"test-source"},"signatures":[]}`),
		"root.json":     []byte(`{"signed":{"version":7},"signatures":[]}`),
		"objects/sha256/" + objectDigest[:2] + "/" + objectDigest: object,
	}
	for name, content := range files {
		writeTestFile(t, root, name, content)
	}
	rootVersion := uint64(7)
	return BuildOptions{
		Root: root, SourceID: "test-source", ManifestDigest: strings.Repeat("a", 64),
		ManifestEnvelopeSHA256: digest(files["manifest.json"]), RootVersion: &rootVersion, Files: files,
	}
}

func verifyOptions(options BuildOptions) BuildOptions {
	options.Root = ""
	options.Output = ""
	return options
}

type testTarEntry struct {
	header tar.Header
	body   []byte
}

func readPackageEntries(t *testing.T, compressed []byte) []testTarEntry {
	t.Helper()
	archive := decodePackage(t, compressed)
	reader := tar.NewReader(bytes.NewReader(archive))
	var entries []testTarEntry
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, testTarEntry{header: *header, body: body})
	}
	return entries
}

func decodePackage(t *testing.T, compressed []byte) []byte {
	t.Helper()
	decoder, err := zstd.NewReader(bytes.NewReader(compressed), zstd.WithDecoderConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	defer decoder.Close()
	archive, err := io.ReadAll(decoder)
	if err != nil {
		t.Fatal(err)
	}
	return archive
}

func writePackageEntries(t *testing.T, output string, entries []testTarEntry, trailing bool) {
	t.Helper()
	var archive bytes.Buffer
	twriter := tar.NewWriter(&archive)
	for _, entry := range entries {
		header := entry.header
		header.Size = int64(len(entry.body))
		if err := twriter.WriteHeader(&header); err != nil {
			t.Fatal(err)
		}
		if _, err := twriter.Write(entry.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := twriter.Close(); err != nil {
		t.Fatal(err)
	}
	writeCompressedArchive(t, output, archive.Bytes())
	if trailing {
		file, err := os.OpenFile(output, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte("trailing")); err != nil {
			file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func writeCompressedArchive(t *testing.T, output string, archive []byte) {
	t.Helper()
	var compressed bytes.Buffer
	encoder, err := zstd.NewWriter(&compressed, zstd.WithEncoderConcurrency(1), zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithEncoderCRC(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := encoder.Write(archive); err != nil {
		t.Fatal(err)
	}
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, compressed.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func updateTarChecksum(header []byte) {
	for index := 148; index < 156; index++ {
		header[index] = ' '
	}
	var sum int64
	for _, value := range header {
		sum += int64(value)
	}
	checksum := []byte(fmt.Sprintf("%06o\x00 ", sum))
	copy(header[148:156], checksum)
}

func mutateMetadata(t *testing.T, entry *testTarEntry, mutate func(*PackageMetadata)) {
	t.Helper()
	var metadata PackageMetadata
	if err := json.Unmarshal(entry.body, &metadata); err != nil {
		t.Fatal(err)
	}
	mutate(&metadata)
	content, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	entry.body = content
	entry.header.Size = int64(len(content))
}

func cloneTarEntries(entries []testTarEntry) []testTarEntry {
	result := make([]testTarEntry, len(entries))
	for index, entry := range entries {
		result[index] = cloneTarEntry(entry)
	}
	return result
}

func cloneTarEntry(entry testTarEntry) testTarEntry {
	entry.body = append([]byte(nil), entry.body...)
	return entry
}

func entryNames(entries []testTarEntry) []string {
	result := make([]string, len(entries))
	for index, entry := range entries {
		result[index] = entry.header.Name
	}
	return result
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func writeTestFile(t *testing.T, root, name string, content []byte) {
	t.Helper()
	filePath := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filePath, content, 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustReadFile(t *testing.T, name string) []byte {
	t.Helper()
	content, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func digest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}
