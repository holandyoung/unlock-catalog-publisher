// Package catalogv1 defines the publisher-owned representation of the public
// Unlock Catalog V1 wire protocol. It intentionally has no platform imports.
package catalogv1

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	SchemaVersion  = 1
	ProtocolV1     = "unlock-catalog-v1"
	MaxSourceBytes = 4 << 20
)

type Permission string

const (
	PermissionMetadata      Permission = "metadata"
	PermissionDetectionData Permission = "detection-data"
	PermissionRoutingData   Permission = "routing-data"
	PermissionExecutable    Permission = "executable"
)

type Cohort struct {
	OS   string `json:"os" yaml:"os"`
	Arch string `json:"arch" yaml:"arch"`
	ABI  string `json:"abi" yaml:"abi"`
}

// Source is declarative publisher input. PublishedAt and ExpiresAt are derived
// from SOURCE_DATE_EPOCH and ValidForSeconds so builds do not read wall time.
type Source struct {
	SchemaVersion      int                  `yaml:"schemaVersion"`
	SourceID           string               `yaml:"sourceId"`
	Version            uint64               `yaml:"version"`
	ValidForSeconds    int64                `yaml:"validForSeconds"`
	MinCoreProtocol    int                  `yaml:"minCoreProtocol"`
	MaxCoreProtocol    int                  `yaml:"maxCoreProtocol"`
	MinCoreVersion     string               `yaml:"minCoreVersion"`
	MaxCoreVersion     string               `yaml:"maxCoreVersion"`
	CompatibilityEpoch int                  `yaml:"compatibilityEpoch"`
	Permissions        []Permission         `yaml:"permissions"`
	Cohort             Cohort               `yaml:"cohort"`
	Entries            []Entry              `yaml:"entries"`
	Artifacts          []ArtifactDescriptor `yaml:"artifacts"`
	Revocations        []Revocation         `yaml:"revocations"`
}

type Manifest struct {
	SchemaVersion      int                  `json:"schemaVersion" yaml:"schemaVersion"`
	Protocol           string               `json:"protocol" yaml:"protocol"`
	SourceID           string               `json:"sourceId" yaml:"sourceId"`
	Version            uint64               `json:"version" yaml:"version"`
	PublishedAt        time.Time            `json:"publishedAt" yaml:"publishedAt"`
	ExpiresAt          time.Time            `json:"expiresAt" yaml:"expiresAt"`
	MinCoreProtocol    int                  `json:"minCoreProtocol" yaml:"minCoreProtocol"`
	MaxCoreProtocol    int                  `json:"maxCoreProtocol" yaml:"maxCoreProtocol"`
	MinCoreVersion     string               `json:"minCoreVersion,omitempty" yaml:"minCoreVersion,omitempty"`
	MaxCoreVersion     string               `json:"maxCoreVersion,omitempty" yaml:"maxCoreVersion,omitempty"`
	CompatibilityEpoch int                  `json:"compatibilityEpoch" yaml:"compatibilityEpoch"`
	Entries            []Entry              `json:"entries" yaml:"entries"`
	Artifacts          []ArtifactDescriptor `json:"artifacts" yaml:"artifacts"`
	Revocations        []Revocation         `json:"revocations" yaml:"revocations"`
}

type Entry struct {
	EntryID            string               `json:"entryId" yaml:"entryId"`
	DisplayComponentID string               `json:"displayComponentId" yaml:"displayComponentId"`
	DisplayName        string               `json:"displayName" yaml:"displayName"`
	Description        string               `json:"description,omitempty" yaml:"description,omitempty"`
	Tags               []string             `json:"tags,omitempty" yaml:"tags,omitempty"`
	Family             FamilyDefinition     `json:"family" yaml:"family"`
	Metadata           []ArtifactComponent  `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	Routing            []RoutingComponent   `json:"routing" yaml:"routing"`
	Detection          []DetectionComponent `json:"detection" yaml:"detection"`
}

type ArtifactComponent struct {
	ComponentID string `json:"componentId" yaml:"componentId"`
	ArtifactID  string `json:"artifactId" yaml:"artifactId"`
}

type RoutingComponent struct {
	ComponentID string       `json:"componentId" yaml:"componentId"`
	Rule        *RoutingRule `json:"rule,omitempty" yaml:"rule,omitempty"`
	ArtifactID  string       `json:"artifactId,omitempty" yaml:"artifactId,omitempty"`
}

type DetectionComponent struct {
	ComponentID string   `json:"componentId" yaml:"componentId"`
	ArtifactIDs []string `json:"artifactIds,omitempty" yaml:"artifactIds,omitempty"`
}

type RoutingRule struct {
	Kind     string `json:"kind" yaml:"kind"`
	Value    string `json:"value,omitempty" yaml:"value,omitempty"`
	Match    string `json:"match,omitempty" yaml:"match,omitempty"`
	Resolve  *bool  `json:"resolve,omitempty" yaml:"resolve,omitempty"`
	URL      string `json:"url,omitempty" yaml:"url,omitempty"`
	Format   string `json:"format,omitempty" yaml:"format,omitempty"`
	Behavior string `json:"behavior,omitempty" yaml:"behavior,omitempty"`
	Interval int    `json:"interval,omitempty" yaml:"interval,omitempty"`
}

type FamilyDefinition struct {
	Name                   string                       `json:"name" yaml:"name"`
	DisplayName            string                       `json:"displayName" yaml:"displayName"`
	DefaultEngine          string                       `json:"defaultEngine" yaml:"defaultEngine"`
	DefaultVariant         string                       `json:"defaultVariant" yaml:"defaultVariant"`
	RoutingEntry           string                       `json:"routingEntry,omitempty" yaml:"routingEntry,omitempty"`
	AllowPinSourceOverride bool                         `json:"allowPinSourceOverride,omitempty" yaml:"allowPinSourceOverride,omitempty"`
	Variants               map[string]VariantDefinition `json:"variants" yaml:"variants"`
	PinPolicy              PinPolicy                    `json:"pinPolicy" yaml:"pinPolicy"`
}

type VariantDefinition struct {
	ID            string              `json:"id" yaml:"id"`
	DisplayName   string              `json:"displayName,omitempty" yaml:"displayName,omitempty"`
	RequiredSlots []string            `json:"requiredSlots" yaml:"requiredSlots"`
	Bindings      []BindingDefinition `json:"bindings" yaml:"bindings"`
}

type BindingDefinition struct {
	ID              string   `json:"id" yaml:"id"`
	DisplayName     string   `json:"displayName,omitempty" yaml:"displayName,omitempty"`
	Engine          string   `json:"engine,omitempty" yaml:"engine,omitempty"`
	Provider        string   `json:"provider" yaml:"provider"`
	Slots           []string `json:"slots" yaml:"slots"`
	IntervalSeconds int      `json:"intervalSeconds,omitempty" yaml:"intervalSeconds,omitempty"`
	TimeoutSeconds  int      `json:"timeoutSeconds,omitempty" yaml:"timeoutSeconds,omitempty"`
}

type PinPolicy struct {
	ComponentID      string   `json:"componentId,omitempty" yaml:"componentId,omitempty"`
	SourceSlot       string   `json:"sourceSlot" yaml:"sourceSlot"`
	AcceptedVerdicts []string `json:"acceptedVerdicts" yaml:"acceptedVerdicts"`
}

type ArtifactDescriptor struct {
	ArtifactID string            `json:"artifactId" yaml:"artifactId"`
	EntryID    string            `json:"entryId" yaml:"entryId"`
	Permission Permission        `json:"permission" yaml:"permission"`
	MediaType  string            `json:"mediaType" yaml:"mediaType"`
	Path       string            `json:"path" yaml:"path"`
	SHA256     string            `json:"sha256" yaml:"sha256"`
	Length     int64             `json:"length" yaml:"length"`
	Platform   *ArtifactPlatform `json:"platform,omitempty" yaml:"platform,omitempty"`
}

type ArtifactPlatform struct {
	OS   string `json:"os" yaml:"os"`
	Arch string `json:"arch" yaml:"arch"`
	ABI  string `json:"abi,omitempty" yaml:"abi,omitempty"`
}

type Revocation struct {
	RevocationID string `json:"revocationId" yaml:"revocationId"`
	Kind         string `json:"kind" yaml:"kind"`
	TargetID     string `json:"targetId" yaml:"targetId"`
	Version      uint64 `json:"version" yaml:"version"`
	Reason       string `json:"reason" yaml:"reason"`
}

type SigningRequest struct {
	SchemaVersion int             `json:"schemaVersion"`
	PolicyVersion string          `json:"policyVersion"`
	SourceID      string          `json:"sourceId"`
	Version       uint64          `json:"version"`
	PayloadSHA256 string          `json:"payloadSha256"`
	PublishedAt   time.Time       `json:"publishedAt"`
	ExpiresAt     time.Time       `json:"expiresAt"`
	Permissions   []Permission    `json:"permissions"`
	Cohort        Cohort          `json:"cohort"`
	Objects       []SigningObject `json:"objects"`
}

type SigningObject struct {
	ArtifactID string            `json:"artifactId"`
	Path       string            `json:"path"`
	SHA256     string            `json:"sha256"`
	Length     int64             `json:"length"`
	Permission Permission        `json:"permission"`
	Platform   *ArtifactPlatform `json:"platform,omitempty"`
}

func DecodeSource(reader io.Reader) (Source, error) {
	content, err := io.ReadAll(io.LimitReader(reader, MaxSourceBytes+1))
	if err != nil {
		return Source{}, fmt.Errorf("read catalog source: %w", err)
	}
	if len(content) > MaxSourceBytes {
		return Source{}, fmt.Errorf("catalog source exceeds %d bytes", MaxSourceBytes)
	}
	if err := validateYAMLDocument(content); err != nil {
		return Source{}, fmt.Errorf("decode catalog source: %w", err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	decoder.KnownFields(true)
	var source Source
	if err := decoder.Decode(&source); err != nil {
		return Source{}, fmt.Errorf("decode catalog source: %w", err)
	}
	return source, nil
}

func validateYAMLDocument(content []byte) error {
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return err
	}
	if err := validateYAMLNode(&document, "$", map[*yaml.Node]struct{}{}); err != nil {
		return err
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple YAML documents")
		}
		return fmt.Errorf("trailing YAML data: %w", err)
	}
	return nil
}

func validateYAMLNode(node *yaml.Node, location string, active map[*yaml.Node]struct{}) error {
	if node == nil {
		return nil
	}
	if _, cycle := active[node]; cycle {
		return fmt.Errorf("%s contains a YAML node cycle", location)
	}
	active[node] = struct{}{}
	defer delete(active, node)
	if node.Anchor != "" || node.Kind == yaml.AliasNode {
		return fmt.Errorf("%s uses forbidden YAML anchor or alias", location)
	}
	switch node.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for index, child := range node.Content {
			if err := validateYAMLNode(child, fmt.Sprintf("%s[%d]", location, index), active); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		if len(node.Content)%2 != 0 {
			return fmt.Errorf("%s has malformed mapping", location)
		}
		seen := make(map[string]struct{}, len(node.Content)/2)
		for index := 0; index < len(node.Content); index += 2 {
			key, value := node.Content[index], node.Content[index+1]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Value == "<<" {
				return fmt.Errorf("%s has non-string or merge mapping key", location)
			}
			if _, duplicate := seen[key.Value]; duplicate {
				return fmt.Errorf("%s repeats mapping key %q", location, key.Value)
			}
			seen[key.Value] = struct{}{}
			if err := validateYAMLNode(value, location+"."+key.Value, active); err != nil {
				return err
			}
		}
	}
	return nil
}

func ManifestFromSource(source Source, publishedAt time.Time) Manifest {
	return Manifest{
		SchemaVersion: source.SchemaVersion, Protocol: ProtocolV1,
		SourceID: source.SourceID, Version: source.Version,
		PublishedAt: publishedAt.UTC(), ExpiresAt: publishedAt.UTC().Add(time.Duration(source.ValidForSeconds) * time.Second),
		MinCoreProtocol: source.MinCoreProtocol, MaxCoreProtocol: source.MaxCoreProtocol,
		MinCoreVersion: source.MinCoreVersion, MaxCoreVersion: source.MaxCoreVersion,
		CompatibilityEpoch: source.CompatibilityEpoch,
		Entries:            source.Entries, Artifacts: source.Artifacts, Revocations: source.Revocations,
	}
}

func CanonicalManifest(manifest Manifest) ([]byte, error) {
	normalized, err := normalizeManifest(manifest)
	if err != nil {
		return nil, err
	}
	return json.Marshal(normalized)
}

func ManifestDigest(manifest Manifest) (string, []byte, error) {
	payload, err := CanonicalManifest(manifest)
	if err != nil {
		return "", nil, err
	}
	return DigestBytes(payload), payload, nil
}

func DigestBytes(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func normalizeManifest(manifest Manifest) (Manifest, error) {
	raw, err := json.Marshal(manifest)
	if err != nil {
		return Manifest{}, err
	}
	var out Manifest
	if err := json.Unmarshal(raw, &out); err != nil {
		return Manifest{}, err
	}
	sort.Slice(out.Entries, func(i, j int) bool { return out.Entries[i].EntryID < out.Entries[j].EntryID })
	for index := range out.Entries {
		normalizeEntry(&out.Entries[index])
	}
	sort.Slice(out.Artifacts, func(i, j int) bool { return out.Artifacts[i].ArtifactID < out.Artifacts[j].ArtifactID })
	sort.Slice(out.Revocations, func(i, j int) bool { return out.Revocations[i].RevocationID < out.Revocations[j].RevocationID })
	return out, nil
}

func normalizeEntry(entry *Entry) {
	sort.Strings(entry.Tags)
	sort.Slice(entry.Metadata, func(i, j int) bool { return entry.Metadata[i].ComponentID < entry.Metadata[j].ComponentID })
	sort.Slice(entry.Routing, func(i, j int) bool { return entry.Routing[i].ComponentID < entry.Routing[j].ComponentID })
	for index := range entry.Detection {
		sort.Strings(entry.Detection[index].ArtifactIDs)
	}
	sort.Slice(entry.Detection, func(i, j int) bool { return entry.Detection[i].ComponentID < entry.Detection[j].ComponentID })
	for id, variant := range entry.Family.Variants {
		sort.Strings(variant.RequiredSlots)
		sort.Slice(variant.Bindings, func(i, j int) bool { return variant.Bindings[i].ID < variant.Bindings[j].ID })
		for index := range variant.Bindings {
			sort.Strings(variant.Bindings[index].Slots)
		}
		entry.Family.Variants[id] = variant
	}
	sort.Strings(entry.Family.PinPolicy.AcceptedVerdicts)
}
