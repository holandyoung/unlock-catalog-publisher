// Package packagefile builds and verifies deterministic offline Catalog packages.
package packagefile

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const maxPackageFileBytes = 256 << 20

var zipEpoch = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)

func BuildPackage(root, output string, expected map[string][]byte) error {
	if root == "" || output == "" || len(expected) == 0 {
		return fmt.Errorf("package root, output, and expected files are required")
	}
	if err := validateExpected(expected); err != nil {
		return err
	}
	found := make(map[string][]byte, len(expected))
	if err := filepath.Walk(root, func(itemPath string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, itemPath)
		if err != nil {
			return err
		}
		if relative == "." {
			if !info.IsDir() {
				return fmt.Errorf("package root must be a directory")
			}
			return nil
		}
		name := filepath.ToSlash(relative)
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("package path %q is a symlink", name)
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 != 0 {
			return fmt.Errorf("package path %q must be a non-executable regular file", name)
		}
		want, ok := expected[name]
		if !ok {
			return fmt.Errorf("package tree contains extra file %q", name)
		}
		content, err := os.ReadFile(itemPath)
		if err != nil {
			return err
		}
		if !bytes.Equal(content, want) {
			return fmt.Errorf("package tree file %q differs from expected bytes", name)
		}
		found[name] = content
		return nil
	}); err != nil {
		return err
	}
	if len(found) != len(expected) {
		return fmt.Errorf("package tree is missing expected files")
	}
	if _, err := os.Lstat(output); err == nil {
		return fmt.Errorf("package output already exists")
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(output), ".catalog-package-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	archive := zip.NewWriter(temporary)
	names := sortedNames(expected)
	for _, name := range names {
		header := &zip.FileHeader{Name: name, Method: zip.Store}
		header.SetModTime(zipEpoch)
		header.SetMode(0o644)
		entry, err := archive.CreateHeader(header)
		if err != nil {
			archive.Close()
			temporary.Close()
			return err
		}
		if _, err := entry.Write(expected[name]); err != nil {
			archive.Close()
			temporary.Close()
			return err
		}
	}
	if err := archive.Close(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Chmod(temporaryPath, 0o644); err != nil {
		return err
	}
	if err := os.Link(temporaryPath, output); err != nil {
		return fmt.Errorf("publish package without overwrite: %w", err)
	}
	return VerifyPackage(output, expected)
}

func VerifyPackage(packagePath string, expected map[string][]byte) error {
	if err := validateExpected(expected); err != nil {
		return err
	}
	info, err := os.Lstat(packagePath)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("package must be a regular file")
	}
	reader, err := zip.OpenReader(packagePath)
	if err != nil {
		return err
	}
	defer reader.Close()
	seen := make(map[string]struct{}, len(reader.File))
	for _, entry := range reader.File {
		if err := validatePath(entry.Name); err != nil {
			return err
		}
		if _, duplicate := seen[entry.Name]; duplicate {
			return fmt.Errorf("package contains duplicate file %q", entry.Name)
		}
		seen[entry.Name] = struct{}{}
		want, ok := expected[entry.Name]
		if !ok {
			return fmt.Errorf("package contains extra file %q", entry.Name)
		}
		if entry.FileInfo().IsDir() || !entry.Mode().IsRegular() || entry.Mode().Perm() != 0o644 || entry.Method != zip.Store {
			return fmt.Errorf("package file %q has non-canonical metadata", entry.Name)
		}
		if entry.UncompressedSize64 > maxPackageFileBytes || entry.UncompressedSize64 != uint64(len(want)) {
			return fmt.Errorf("package file %q has invalid length", entry.Name)
		}
		file, err := entry.Open()
		if err != nil {
			return err
		}
		content, readErr := io.ReadAll(io.LimitReader(file, maxPackageFileBytes+1))
		closeErr := file.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if !bytes.Equal(content, want) {
			return fmt.Errorf("package file %q differs from expected bytes", entry.Name)
		}
	}
	if len(seen) != len(expected) {
		return fmt.Errorf("package is missing expected files")
	}
	return nil
}

func validateExpected(expected map[string][]byte) error {
	for name := range expected {
		if err := validatePath(name); err != nil {
			return err
		}
	}
	return nil
}

func validatePath(name string) error {
	if name == "" || strings.Contains(name, "\\") || path.IsAbs(name) || path.Clean(name) != name || name == "." || strings.HasPrefix(name, "../") {
		return fmt.Errorf("unsafe package path %q", name)
	}
	return nil
}

func sortedNames(files map[string][]byte) []string {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
