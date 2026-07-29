package policy

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/holandyoung/unlock-catalog-publisher/internal/catalogv1"
)

func validDataSource() catalogv1.Source {
	digest := strings.Repeat("a", 64)
	return catalogv1.Source{
		SchemaVersion: 1, SourceID: DataSourceID, Version: 1, ValidForSeconds: 14 * 24 * 60 * 60,
		MinCoreProtocol: 1, MaxCoreProtocol: 2, MinCoreVersion: "1.0.0", MaxCoreVersion: "2.0.0",
		CompatibilityEpoch: 1,
		Permissions: []catalogv1.Permission{
			catalogv1.PermissionMetadata,
			catalogv1.PermissionDetectionData,
			catalogv1.PermissionRoutingData,
		},
		Cohort: catalogv1.Cohort{OS: "linux", Arch: "amd64", ABI: "static"},
		Entries: []catalogv1.Entry{{
			EntryID: "example", DisplayComponentID: "example-display", DisplayName: "Example",
			Family: catalogv1.FamilyDefinition{
				Name: "example", DisplayName: "Example", DefaultEngine: "mediaunlocktest",
				DefaultVariant: "global", RoutingEntry: "example",
				Variants: map[string]catalogv1.VariantDefinition{
					"global": {
						ID: "global", DisplayName: "Global", RequiredSlots: []string{"availability"},
						Bindings: []catalogv1.BindingDefinition{{ID: "example-check", Provider: "example", Slots: []string{"availability"}}},
					},
				},
				PinPolicy: catalogv1.PinPolicy{ComponentID: "example-check", SourceSlot: "availability", AcceptedVerdicts: []string{"unlocked"}},
			},
			Metadata:  []catalogv1.ArtifactComponent{{ComponentID: "example-metadata", ArtifactID: "example-metadata-object"}},
			Routing:   []catalogv1.RoutingComponent{{ComponentID: "example-route", Rule: &catalogv1.RoutingRule{Kind: "domain", Value: "example.test"}}},
			Detection: []catalogv1.DetectionComponent{{ComponentID: "example-check"}},
		}},
		Artifacts: []catalogv1.ArtifactDescriptor{{
			ArtifactID: "example-metadata-object", EntryID: "example",
			Permission: catalogv1.PermissionMetadata, MediaType: "application/json",
			Path: "objects/sha256/aa/" + digest, SHA256: digest, Length: 1,
		}},
		Revocations: []catalogv1.Revocation{},
	}
}

func TestValidateAcceptsSeparatedDataAndExecutableSources(t *testing.T) {
	data := validDataSource()
	if err := Validate(data, filepath.Join(t.TempDir(), DataSourceID)); err != nil {
		t.Fatalf("data source: %v", err)
	}

	exec := validDataSource()
	exec.SourceID = ExecSourceID
	exec.Permissions = append(exec.Permissions, catalogv1.PermissionExecutable)
	execArtifact := catalogv1.ArtifactDescriptor{
		ArtifactID: "example-helper", EntryID: "example", Permission: catalogv1.PermissionExecutable,
		MediaType: "application/octet-stream", SHA256: strings.Repeat("b", 64), Length: 1,
		Path:     "objects/sha256/bb/" + strings.Repeat("b", 64),
		Platform: &catalogv1.ArtifactPlatform{OS: "linux", Arch: "amd64", ABI: "static"},
	}
	exec.Artifacts = append(exec.Artifacts, execArtifact)
	exec.Entries[0].Detection[0].ArtifactIDs = []string{execArtifact.ArtifactID}
	if err := Validate(exec, filepath.Join(t.TempDir(), ExecSourceID)); err != nil {
		t.Fatalf("exec source: %v", err)
	}
}

func TestValidateRejectsPolicyBoundaryViolations(t *testing.T) {
	for name, mutate := range map[string]func(*catalogv1.Source, *string){
		"duplicate stable id": func(source *catalogv1.Source, _ *string) {
			source.Entries = append(source.Entries, source.Entries[0])
		},
		"permission bleed": func(source *catalogv1.Source, _ *string) {
			source.Artifacts[0].Permission = catalogv1.PermissionExecutable
			source.Artifacts[0].MediaType = "application/octet-stream"
			source.Artifacts[0].Platform = &catalogv1.ArtifactPlatform{OS: "linux", Arch: "amd64", ABI: "static"}
		},
		"source identity mismatch": func(_ *catalogv1.Source, root *string) {
			*root = filepath.Join(filepath.Dir(*root), "other-source")
		},
		"non-canonical path": func(source *catalogv1.Source, _ *string) {
			source.Artifacts[0].Path = "objects/../payload"
		},
		"digest path mismatch": func(source *catalogv1.Source, _ *string) {
			source.Artifacts[0].Path = "objects/sha256/bb/" + source.Artifacts[0].SHA256
		},
		"default source executable": func(source *catalogv1.Source, _ *string) {
			source.Permissions = append(source.Permissions, catalogv1.PermissionExecutable)
		},
		"wrong os": func(source *catalogv1.Source, _ *string) {
			source.Cohort.OS = "darwin"
		},
		"wrong architecture": func(source *catalogv1.Source, _ *string) {
			source.Cohort.Arch = "arm64"
		},
		"wrong abi": func(source *catalogv1.Source, _ *string) {
			source.Cohort.ABI = "gnu"
		},
	} {
		t.Run(name, func(t *testing.T) {
			source := validDataSource()
			root := filepath.Join(t.TempDir(), DataSourceID)
			mutate(&source, &root)
			if err := Validate(source, root); err == nil {
				t.Fatal("invalid policy was accepted")
			}
		})
	}
}
