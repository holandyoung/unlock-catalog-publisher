package signing

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/holandyoung/unlock-catalog-publisher/internal/catalogv1"
	"github.com/holandyoung/unlock-catalog-publisher/internal/policy"
)

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func inspectCandidate(candidateRoot string) (*PreparedCandidate, error) {
	root, err := validateCandidateRoot(candidateRoot)
	if err != nil {
		return nil, err
	}
	payload, err := readRegularFile(filepath.Join(root, manifestPayloadName), maxPayloadBytes, false)
	if err != nil {
		return nil, fmt.Errorf("read manifest payload: %w", err)
	}
	requestBytes, err := readRegularFile(filepath.Join(root, signingRequestName), maxRequestBytes, false)
	if err != nil {
		return nil, fmt.Errorf("read signing request: %w", err)
	}

	var manifest catalogv1.Manifest
	if err := decodeStrictJSON(payload, &manifest); err != nil {
		return nil, fmt.Errorf("decode manifest payload: %w", err)
	}
	canonicalPayload, err := catalogv1.CanonicalManifest(manifest)
	if err != nil {
		return nil, fmt.Errorf("canonicalize manifest payload: %w", err)
	}
	if !bytes.Equal(payload, canonicalPayload) {
		return nil, fmt.Errorf("manifest payload is not canonical")
	}

	var request SigningRequest
	if err := decodeStrictJSON(requestBytes, &request); err != nil {
		return nil, fmt.Errorf("decode signing request: %w", err)
	}
	canonicalRequest, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("canonicalize signing request: %w", err)
	}
	if !bytes.Equal(requestBytes, canonicalRequest) {
		return nil, fmt.Errorf("signing request is not canonical")
	}
	if filepath.Base(root) != request.SourceID {
		return nil, fmt.Errorf("candidate directory identity does not match sourceId %q", request.SourceID)
	}
	if err := validateRequestAndPolicy(manifest, request, payload); err != nil {
		return nil, err
	}
	if err := validateCandidateTree(root, request); err != nil {
		return nil, err
	}
	if err := validateObjects(root, request); err != nil {
		return nil, err
	}

	return &PreparedCandidate{
		inspection: Inspection{
			SourceID:      request.SourceID,
			Version:       request.Version,
			RequestDigest: catalogv1.DigestBytes(requestBytes),
			PayloadSHA256: request.PayloadSHA256,
			ObjectCount:   len(request.Objects),
		},
		payload: append([]byte(nil), payload...),
	}, nil
}

func validateRequestAndPolicy(manifest catalogv1.Manifest, request SigningRequest, payload []byte) error {
	if manifest.SchemaVersion != catalogv1.SchemaVersion || manifest.Protocol != catalogv1.ProtocolV1 {
		return fmt.Errorf("manifest schema or protocol mismatch")
	}
	if request.SchemaVersion != catalogv1.SchemaVersion || request.PolicyVersion != policy.PolicyVersion {
		return fmt.Errorf("signing request schema or policy mismatch")
	}
	if request.SourceID != manifest.SourceID || request.Version != manifest.Version ||
		!request.PublishedAt.Equal(manifest.PublishedAt) || !request.ExpiresAt.Equal(manifest.ExpiresAt) {
		return fmt.Errorf("signing request source, version, or validity mismatch")
	}
	if !isUTCSecond(request.PublishedAt) || !isUTCSecond(request.ExpiresAt) ||
		!isUTCSecond(manifest.PublishedAt) || !isUTCSecond(manifest.ExpiresAt) {
		return fmt.Errorf("candidate validity must use UTC whole seconds")
	}
	if request.PayloadSHA256 != catalogv1.DigestBytes(payload) {
		return fmt.Errorf("signing request payload digest mismatch")
	}
	validFor := request.ExpiresAt.Sub(request.PublishedAt)
	if validFor <= 0 || validFor%time.Second != 0 {
		return fmt.Errorf("signing request validity is not an exact positive number of seconds")
	}
	source := catalogv1.Source{
		SchemaVersion:      manifest.SchemaVersion,
		SourceID:           manifest.SourceID,
		Version:            manifest.Version,
		ValidForSeconds:    int64(validFor / time.Second),
		MinCoreProtocol:    manifest.MinCoreProtocol,
		MaxCoreProtocol:    manifest.MaxCoreProtocol,
		MinCoreVersion:     manifest.MinCoreVersion,
		MaxCoreVersion:     manifest.MaxCoreVersion,
		CompatibilityEpoch: manifest.CompatibilityEpoch,
		Permissions:        append([]catalogv1.Permission(nil), request.Permissions...),
		Cohort:             request.Cohort,
		Entries:            manifest.Entries,
		Artifacts:          manifest.Artifacts,
		Revocations:        manifest.Revocations,
	}
	if err := policy.Validate(source, filepath.Join(string(filepath.Separator), "candidate", source.SourceID)); err != nil {
		return fmt.Errorf("candidate policy: %w", err)
	}
	if len(request.Objects) != len(manifest.Artifacts) {
		return fmt.Errorf("signing request object count mismatch")
	}
	for index := range manifest.Artifacts {
		artifact := manifest.Artifacts[index]
		object := request.Objects[index]
		if object.ArtifactID != artifact.ArtifactID || object.Path != artifact.Path ||
			object.SHA256 != artifact.SHA256 || object.Length != artifact.Length ||
			object.Permission != artifact.Permission || !reflect.DeepEqual(object.Platform, artifact.Platform) {
			return fmt.Errorf("signing request object %q does not match manifest", object.ArtifactID)
		}
		if index > 0 && request.Objects[index-1].ArtifactID >= object.ArtifactID {
			return fmt.Errorf("signing request objects are not uniquely sorted")
		}
	}
	return nil
}

func isUTCSecond(value time.Time) bool {
	_, offset := value.Zone()
	return offset == 0 && value.Nanosecond() == 0
}

func validateCandidateRoot(candidateRoot string) (string, error) {
	absolute, err := filepath.Abs(candidateRoot)
	if err != nil {
		return "", fmt.Errorf("resolve candidate root: %w", err)
	}
	root, err := openNoSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("securely open candidate root: %w", err)
	}
	defer root.Close()
	info, err := root.Stat()
	if err != nil {
		return "", fmt.Errorf("inspect candidate root: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o755 {
		return "", fmt.Errorf("candidate root must be a mode 0755 real directory")
	}
	return absolute, nil
}

func validateCandidateTree(root string, request SigningRequest) error {
	expectedFiles := map[string]struct{}{manifestPayloadName: {}, signingRequestName: {}}
	expectedDirectories := make(map[string]struct{})
	for _, object := range request.Objects {
		if !validRelativePath(object.Path) {
			return fmt.Errorf("candidate object path %q is invalid", object.Path)
		}
		expectedFiles[object.Path] = struct{}{}
		for parent := path.Dir(object.Path); parent != "."; parent = path.Dir(parent) {
			expectedDirectories[parent] = struct{}{}
		}
	}
	seen := make(map[string]struct{}, len(expectedFiles))
	err := filepath.WalkDir(root, func(itemPath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, itemPath)
		if err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		relative = filepath.ToSlash(relative)
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("candidate path %q is a symlink", relative)
		}
		if entry.IsDir() {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if info.Mode().Perm() != 0o755 {
				return fmt.Errorf("candidate directory %q must have mode 0755", relative)
			}
			if _, ok := expectedDirectories[relative]; !ok {
				return fmt.Errorf("candidate contains unknown directory %q", relative)
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !validCandidateFileMode(info.Mode()) {
			return fmt.Errorf("candidate path %q must be a non-executable regular file", relative)
		}
		if _, ok := expectedFiles[relative]; !ok {
			return fmt.Errorf("candidate contains unknown file %q", relative)
		}
		if _, duplicate := seen[relative]; duplicate {
			return fmt.Errorf("candidate repeats file %q", relative)
		}
		seen[relative] = struct{}{}
		return nil
	})
	if err != nil {
		return err
	}
	for expected := range expectedFiles {
		if _, ok := seen[expected]; !ok {
			return fmt.Errorf("candidate is missing file %q", expected)
		}
	}
	return nil
}

func validateObjects(root string, request SigningRequest) error {
	for _, object := range request.Objects {
		content, err := readRegularFile(filepath.Join(root, filepath.FromSlash(object.Path)), object.Length, true)
		if err != nil {
			return fmt.Errorf("read object %q: %w", object.ArtifactID, err)
		}
		if int64(len(content)) != object.Length {
			return fmt.Errorf("object %q length mismatch", object.ArtifactID)
		}
		if catalogv1.DigestBytes(content) != object.SHA256 {
			return fmt.Errorf("object %q digest mismatch", object.ArtifactID)
		}
	}
	return nil
}

func readRegularFile(filePath string, maximum int64, exactLimit bool) ([]byte, error) {
	file, err := openNoSymlinks(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !validCandidateFileMode(info.Mode()) {
		return nil, fmt.Errorf("must be a mode 0644 regular file")
	}
	if maximum < 0 {
		return nil, fmt.Errorf("invalid maximum length")
	}
	limit := maximum + 1
	content, err := io.ReadAll(io.LimitReader(file, limit))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > maximum {
		return nil, fmt.Errorf("file exceeds %d bytes", maximum)
	}
	if exactLimit && int64(len(content)) != maximum {
		return nil, fmt.Errorf("file length mismatch")
	}
	return content, nil
}

func validCandidateFileMode(mode fs.FileMode) bool {
	return mode.IsRegular() && mode.Perm() == 0o644
}

func validRelativePath(value string) bool {
	if value == "" || strings.Contains(value, `\`) || strings.HasPrefix(value, "/") || path.Clean(value) != value {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func decodeStrictJSON(content []byte, target any) error {
	if len(content) == 0 {
		return fmt.Errorf("empty JSON document")
	}
	if err := rejectDuplicateJSONMembers(content); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return err
	}
	return nil
}

func rejectDuplicateJSONMembers(content []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	if err := consumeJSONValue(decoder, "$"); err != nil {
		return err
	}
	return ensureJSONEOF(decoder)
}

func consumeJSONValue(decoder *json.Decoder, location string) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("%s has a non-string member name", location)
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("%s repeats JSON member %q", location, key)
			}
			seen[key] = struct{}{}
			if err := consumeJSONValue(decoder, location+"."+key); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return fmt.Errorf("%s has malformed object", location)
		}
	case '[':
		index := 0
		for decoder.More() {
			if err := consumeJSONValue(decoder, fmt.Sprintf("%s[%d]", location, index)); err != nil {
				return err
			}
			index++
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return fmt.Errorf("%s has malformed array", location)
		}
	default:
		return fmt.Errorf("%s begins with unexpected delimiter %q", location, delimiter)
	}
	return nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON value")
		}
		return fmt.Errorf("trailing JSON data: %w", err)
	}
	return nil
}
