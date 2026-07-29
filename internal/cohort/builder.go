// Package cohort builds one immutable, unsigned candidate per source cohort.
package cohort

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"time"

	"github.com/holandyoung/unlock-catalog/internal/catalogv1"
	"github.com/holandyoung/unlock-catalog/internal/policy"
)

const (
	ManifestPayloadName = "manifest.payload.json"
	SigningRequestName  = "signing-request.json"
)

type Candidate struct {
	SourceID      string
	Directory     string
	PayloadSHA256 string
}

type verifiedObject struct {
	descriptor catalogv1.ArtifactDescriptor
	content    []byte
}

func BuildCandidate(sourceFile, outputRoot string, epoch time.Time) (Candidate, error) {
	if epoch.IsZero() || !epoch.Equal(epoch.UTC()) {
		return Candidate{}, fmt.Errorf("SOURCE_DATE_EPOCH must resolve to a non-zero UTC time")
	}
	if filepath.Base(sourceFile) != "source.yaml" {
		return Candidate{}, fmt.Errorf("source document must be named source.yaml")
	}
	sourceInfo, err := os.Lstat(sourceFile)
	if err != nil {
		return Candidate{}, fmt.Errorf("inspect source document: %w", err)
	}
	if !sourceInfo.Mode().IsRegular() || sourceInfo.Mode().Perm()&0o111 != 0 {
		return Candidate{}, fmt.Errorf("source document must be a non-executable regular file")
	}
	file, err := os.Open(sourceFile)
	if err != nil {
		return Candidate{}, fmt.Errorf("open source document: %w", err)
	}
	source, decodeErr := catalogv1.DecodeSource(file)
	closeErr := file.Close()
	if decodeErr != nil {
		return Candidate{}, decodeErr
	}
	if closeErr != nil {
		return Candidate{}, fmt.Errorf("close source document: %w", closeErr)
	}
	sourceRoot := filepath.Dir(sourceFile)
	if err := policy.Validate(source, sourceRoot); err != nil {
		return Candidate{}, fmt.Errorf("source policy: %w", err)
	}
	if err := validateSourceTree(sourceRoot, source.Artifacts); err != nil {
		return Candidate{}, err
	}

	objects := make([]verifiedObject, 0, len(source.Artifacts))
	for _, descriptor := range source.Artifacts {
		objectPath := filepath.Join(sourceRoot, filepath.FromSlash(descriptor.Path))
		info, err := os.Lstat(objectPath)
		if err != nil {
			return Candidate{}, fmt.Errorf("inspect object %q: %w", descriptor.ArtifactID, err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 != 0 {
			return Candidate{}, fmt.Errorf("object %q must be a non-executable regular file", descriptor.ArtifactID)
		}
		content, err := os.ReadFile(objectPath)
		if err != nil {
			return Candidate{}, fmt.Errorf("read object %q: %w", descriptor.ArtifactID, err)
		}
		if int64(len(content)) != descriptor.Length {
			return Candidate{}, fmt.Errorf("object %q length mismatch", descriptor.ArtifactID)
		}
		if catalogv1.DigestBytes(content) != descriptor.SHA256 {
			return Candidate{}, fmt.Errorf("object %q digest mismatch", descriptor.ArtifactID)
		}
		objects = append(objects, verifiedObject{descriptor: descriptor, content: content})
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].descriptor.ArtifactID < objects[j].descriptor.ArtifactID })

	manifest := catalogv1.ManifestFromSource(source, epoch)
	payloadDigest, payload, err := catalogv1.ManifestDigest(manifest)
	if err != nil {
		return Candidate{}, fmt.Errorf("canonical manifest: %w", err)
	}
	request := catalogv1.SigningRequest{
		SchemaVersion: catalogv1.SchemaVersion,
		PolicyVersion: policy.PolicyVersion,
		SourceID:      source.SourceID,
		Version:       source.Version,
		PayloadSHA256: payloadDigest,
		PublishedAt:   manifest.PublishedAt,
		ExpiresAt:     manifest.ExpiresAt,
		Permissions:   append([]catalogv1.Permission(nil), source.Permissions...),
		Cohort:        source.Cohort,
		Objects:       make([]catalogv1.SigningObject, 0, len(objects)),
	}
	for _, object := range objects {
		request.Objects = append(request.Objects, catalogv1.SigningObject{
			ArtifactID: object.descriptor.ArtifactID,
			Path:       object.descriptor.Path, SHA256: object.descriptor.SHA256, Length: object.descriptor.Length,
			Permission: object.descriptor.Permission, Platform: object.descriptor.Platform,
		})
	}
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return Candidate{}, fmt.Errorf("canonical signing request: %w", err)
	}

	destination := filepath.Join(outputRoot, source.SourceID)
	if _, err := os.Lstat(destination); err == nil {
		return Candidate{}, fmt.Errorf("candidate destination already exists: %s", destination)
	} else if !os.IsNotExist(err) {
		return Candidate{}, fmt.Errorf("inspect candidate destination: %w", err)
	}
	if err := os.MkdirAll(outputRoot, 0o755); err != nil {
		return Candidate{}, fmt.Errorf("create output root: %w", err)
	}
	temporary, err := os.MkdirTemp(outputRoot, ".candidate-*")
	if err != nil {
		return Candidate{}, fmt.Errorf("create candidate staging directory: %w", err)
	}
	defer os.RemoveAll(temporary)
	if err := writeCandidate(temporary, payload, requestBytes, objects); err != nil {
		return Candidate{}, err
	}
	if err := os.Rename(temporary, destination); err != nil {
		return Candidate{}, fmt.Errorf("publish candidate directory: %w", err)
	}
	return Candidate{SourceID: source.SourceID, Directory: destination, PayloadSHA256: payloadDigest}, nil
}

func validateSourceTree(sourceRoot string, artifacts []catalogv1.ArtifactDescriptor) error {
	allowedFiles := map[string]struct{}{"source.yaml": {}}
	allowedDirectories := make(map[string]struct{})
	for _, artifact := range artifacts {
		allowedFiles[artifact.Path] = struct{}{}
		for parent := path.Dir(artifact.Path); parent != "."; parent = path.Dir(parent) {
			allowedDirectories[parent] = struct{}{}
		}
	}
	return filepath.WalkDir(sourceRoot, func(itemPath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(sourceRoot, itemPath)
		if err != nil {
			return err
		}
		if relative == "." {
			if !entry.IsDir() {
				return fmt.Errorf("source root must be a real directory")
			}
			return nil
		}
		relative = filepath.ToSlash(relative)
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("source tree path %q is a symlink", relative)
		}
		if entry.IsDir() {
			if _, ok := allowedDirectories[relative]; !ok {
				return fmt.Errorf("source tree contains undeclared directory %q", relative)
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 != 0 {
			return fmt.Errorf("source tree path %q must be a non-executable regular file", relative)
		}
		if _, ok := allowedFiles[relative]; !ok {
			return fmt.Errorf("source tree contains undeclared file %q", relative)
		}
		return nil
	})
}

func writeCandidate(directory string, payload, request []byte, objects []verifiedObject) error {
	if err := os.WriteFile(filepath.Join(directory, ManifestPayloadName), payload, 0o644); err != nil {
		return fmt.Errorf("write manifest payload: %w", err)
	}
	if err := os.WriteFile(filepath.Join(directory, SigningRequestName), request, 0o644); err != nil {
		return fmt.Errorf("write signing request: %w", err)
	}
	for _, object := range objects {
		path := filepath.Join(directory, filepath.FromSlash(object.descriptor.Path))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return fmt.Errorf("create object directory: %w", err)
		}
		if err := os.WriteFile(path, object.content, 0o644); err != nil {
			return fmt.Errorf("write object %q: %w", object.descriptor.ArtifactID, err)
		}
	}
	return nil
}
