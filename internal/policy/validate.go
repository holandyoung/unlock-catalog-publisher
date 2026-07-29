// Package policy applies publisher policy that is intentionally narrower than
// the public Catalog V1 wire protocol.
package policy

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/holandyoung/unlock-catalog-publisher/internal/catalogv1"
)

const (
	PolicyVersion = "unlock-catalog-publisher-policy-v1"
	DataSourceID  = "unlock-official-linux-amd64-static"
	ExecSourceID  = "unlock-official-linux-amd64-static-exec"
	maxLifetime   = 30 * 24 * 60 * 60
	maxObjectSize = 64 << 20
)

var (
	stableID = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	digest   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	version  = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
)

func Validate(source catalogv1.Source, sourceRoot string) error {
	if filepath.Base(filepath.Clean(sourceRoot)) != source.SourceID {
		return fmt.Errorf("source root identity does not match sourceId %q", source.SourceID)
	}
	if source.SchemaVersion != catalogv1.SchemaVersion || source.Version == 0 {
		return fmt.Errorf("schemaVersion and positive version are required")
	}
	if source.ValidForSeconds <= 0 || source.ValidForSeconds > maxLifetime {
		return fmt.Errorf("validForSeconds must be within publisher policy")
	}
	if source.MinCoreProtocol <= 0 || source.MaxCoreProtocol < source.MinCoreProtocol ||
		!version.MatchString(source.MinCoreVersion) || !version.MatchString(source.MaxCoreVersion) ||
		source.CompatibilityEpoch <= 0 {
		return fmt.Errorf("invalid compatibility policy")
	}
	if source.Cohort != (catalogv1.Cohort{OS: "linux", Arch: "amd64", ABI: "static"}) {
		return fmt.Errorf("unsupported cohort %s/%s/%s", source.Cohort.OS, source.Cohort.Arch, source.Cohort.ABI)
	}

	wantPermissions := []catalogv1.Permission{
		catalogv1.PermissionMetadata,
		catalogv1.PermissionDetectionData,
		catalogv1.PermissionRoutingData,
	}
	switch source.SourceID {
	case DataSourceID:
	case ExecSourceID:
		wantPermissions = append(wantPermissions, catalogv1.PermissionExecutable)
	default:
		return fmt.Errorf("unknown publisher source identity %q", source.SourceID)
	}
	if !equalPermissions(source.Permissions, wantPermissions) {
		return fmt.Errorf("source %q permissions do not match policy", source.SourceID)
	}

	entries := make(map[string]catalogv1.Entry, len(source.Entries))
	components := make(map[string]string)
	for _, entry := range source.Entries {
		if !validID(entry.EntryID) {
			return fmt.Errorf("invalid entry stable ID %q", entry.EntryID)
		}
		if _, duplicate := entries[entry.EntryID]; duplicate {
			return fmt.Errorf("duplicate entry stable ID %q", entry.EntryID)
		}
		if err := validateEntry(entry, components); err != nil {
			return fmt.Errorf("entry %q: %w", entry.EntryID, err)
		}
		entries[entry.EntryID] = entry
	}
	if len(entries) == 0 {
		return fmt.Errorf("source has no entries")
	}

	allowed := make(map[catalogv1.Permission]struct{}, len(source.Permissions))
	for _, permission := range source.Permissions {
		allowed[permission] = struct{}{}
	}
	artifacts := make(map[string]catalogv1.ArtifactDescriptor, len(source.Artifacts))
	hasExecutable := false
	for _, artifact := range source.Artifacts {
		if !validID(artifact.ArtifactID) || !validID(artifact.EntryID) {
			return fmt.Errorf("invalid artifact identity")
		}
		if _, duplicate := artifacts[artifact.ArtifactID]; duplicate {
			return fmt.Errorf("duplicate artifact stable ID %q", artifact.ArtifactID)
		}
		if _, ok := entries[artifact.EntryID]; !ok {
			return fmt.Errorf("artifact %q has unknown owner %q", artifact.ArtifactID, artifact.EntryID)
		}
		if _, ok := allowed[artifact.Permission]; !ok {
			return fmt.Errorf("artifact %q permission %q bleeds outside source policy", artifact.ArtifactID, artifact.Permission)
		}
		if err := validateArtifact(artifact, source.Cohort); err != nil {
			return err
		}
		hasExecutable = hasExecutable || artifact.Permission == catalogv1.PermissionExecutable
		artifacts[artifact.ArtifactID] = artifact
	}
	if len(artifacts) == 0 {
		return fmt.Errorf("source has no artifacts")
	}
	if source.SourceID == DataSourceID && hasExecutable {
		return fmt.Errorf("default data source contains executable content")
	}
	if source.SourceID == ExecSourceID && !hasExecutable {
		return fmt.Errorf("explicit executable source has no executable artifact")
	}
	if err := validateReferences(source.Entries, artifacts); err != nil {
		return err
	}
	if err := validateRevocations(source); err != nil {
		return err
	}
	return nil
}

func equalPermissions(got, want []catalogv1.Permission) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range want {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}

func validateEntry(entry catalogv1.Entry, components map[string]string) error {
	if !validID(entry.DisplayComponentID) || strings.TrimSpace(entry.DisplayName) == "" {
		return fmt.Errorf("invalid display identity")
	}
	if err := addComponent(components, entry.DisplayComponentID, entry.EntryID); err != nil {
		return err
	}
	if entry.Family.Name != entry.EntryID || entry.Family.RoutingEntry != entry.EntryID ||
		!validID(entry.Family.DefaultEngine) || !validID(entry.Family.DefaultVariant) ||
		len(entry.Family.Variants) == 0 {
		return fmt.Errorf("invalid family baseline")
	}
	if _, ok := entry.Family.Variants[entry.Family.DefaultVariant]; !ok {
		return fmt.Errorf("default variant is missing")
	}
	if !validSlot(entry.Family.PinPolicy.SourceSlot) || len(entry.Family.PinPolicy.AcceptedVerdicts) == 0 {
		return fmt.Errorf("invalid pin policy")
	}

	bindingIDs := make(map[string]struct{})
	for variantID, variant := range entry.Family.Variants {
		if !validID(variantID) || variant.ID != variantID || len(variant.RequiredSlots) == 0 || len(variant.Bindings) == 0 {
			return fmt.Errorf("invalid variant %q", variantID)
		}
		required := make(map[string]struct{}, len(variant.RequiredSlots))
		for _, slot := range variant.RequiredSlots {
			if !validSlot(slot) {
				return fmt.Errorf("invalid required slot %q", slot)
			}
			if _, duplicate := required[slot]; duplicate {
				return fmt.Errorf("duplicate required slot %q", slot)
			}
			required[slot] = struct{}{}
		}
		writers := make(map[string]string)
		variantBindings := make(map[string]struct{})
		for _, binding := range variant.Bindings {
			if !validID(binding.ID) || strings.TrimSpace(binding.Provider) == "" || len(binding.Slots) == 0 {
				return fmt.Errorf("invalid binding")
			}
			if _, duplicate := variantBindings[binding.ID]; duplicate {
				return fmt.Errorf("duplicate binding stable ID %q", binding.ID)
			}
			variantBindings[binding.ID] = struct{}{}
			bindingIDs[binding.ID] = struct{}{}
			for _, slot := range binding.Slots {
				if _, ok := required[slot]; !ok {
					return fmt.Errorf("binding writes undeclared slot %q", slot)
				}
				if prior, duplicate := writers[slot]; duplicate {
					return fmt.Errorf("bindings %q and %q both write slot %q", prior, binding.ID, slot)
				}
				writers[slot] = binding.ID
			}
		}
		if len(writers) != len(required) {
			return fmt.Errorf("required slot has no writer")
		}
	}

	for _, component := range entry.Metadata {
		if !validID(component.ComponentID) || !validID(component.ArtifactID) {
			return fmt.Errorf("invalid metadata component")
		}
		if err := addComponent(components, component.ComponentID, entry.EntryID); err != nil {
			return err
		}
	}
	for _, component := range entry.Routing {
		if !validID(component.ComponentID) || component.Rule == nil || component.Rule.URL != "" {
			return fmt.Errorf("invalid routing component")
		}
		if err := addComponent(components, component.ComponentID, entry.EntryID); err != nil {
			return err
		}
		if component.ArtifactID == "" {
			if component.Rule.Kind != "domain" && component.Rule.Kind != "geosite" && component.Rule.Kind != "geoip" {
				return fmt.Errorf("invalid inline routing rule")
			}
		} else if !validID(component.ArtifactID) || component.Rule.Kind != "ruleset" || component.Rule.Interval <= 0 {
			return fmt.Errorf("invalid artifact routing rule")
		}
	}
	detectionIDs := make(map[string]struct{})
	for _, component := range entry.Detection {
		if !validID(component.ComponentID) {
			return fmt.Errorf("invalid detection component")
		}
		if err := addComponent(components, component.ComponentID, entry.EntryID); err != nil {
			return err
		}
		if _, ok := bindingIDs[component.ComponentID]; !ok {
			return fmt.Errorf("detection component has no family binding")
		}
		detectionIDs[component.ComponentID] = struct{}{}
	}
	for bindingID := range bindingIDs {
		if _, ok := detectionIDs[bindingID]; !ok {
			return fmt.Errorf("family binding %q has no detection component", bindingID)
		}
	}
	return nil
}

func addComponent(components map[string]string, componentID, entryID string) error {
	if prior, duplicate := components[componentID]; duplicate {
		return fmt.Errorf("duplicate component stable ID %q in %q and %q", componentID, prior, entryID)
	}
	components[componentID] = entryID
	return nil
}

func validateArtifact(artifact catalogv1.ArtifactDescriptor, cohort catalogv1.Cohort) error {
	if !digest.MatchString(artifact.SHA256) || artifact.Length <= 0 || artifact.Length > maxObjectSize {
		return fmt.Errorf("artifact %q has invalid digest or length", artifact.ArtifactID)
	}
	wantPath := "objects/sha256/" + artifact.SHA256[:2] + "/" + artifact.SHA256
	if artifact.Path != wantPath {
		return fmt.Errorf("artifact %q path is not canonical content-addressed path", artifact.ArtifactID)
	}
	if !mediaAllowed(artifact.Permission, artifact.MediaType) {
		return fmt.Errorf("artifact %q media type %q is not allowed", artifact.ArtifactID, artifact.MediaType)
	}
	if artifact.Permission == catalogv1.PermissionExecutable {
		if artifact.Platform == nil || *artifact.Platform != (catalogv1.ArtifactPlatform{OS: cohort.OS, Arch: cohort.Arch, ABI: cohort.ABI}) {
			return fmt.Errorf("executable artifact %q platform does not match cohort", artifact.ArtifactID)
		}
	} else if artifact.Platform != nil {
		return fmt.Errorf("non-executable artifact %q has platform metadata", artifact.ArtifactID)
	}
	return nil
}

func mediaAllowed(permission catalogv1.Permission, mediaType string) bool {
	switch permission {
	case catalogv1.PermissionMetadata, catalogv1.PermissionDetectionData:
		return mediaType == "application/json" || mediaType == "application/yaml" || mediaType == "text/plain" || mediaType == "application/octet-stream"
	case catalogv1.PermissionRoutingData:
		return mediaType == "application/json" || mediaType == "application/yaml" || mediaType == "text/plain" || mediaType == "application/vnd.mihomo.mrs"
	case catalogv1.PermissionExecutable:
		return mediaType == "application/octet-stream"
	default:
		return false
	}
}

func validateReferences(entries []catalogv1.Entry, artifacts map[string]catalogv1.ArtifactDescriptor) error {
	references := make(map[string]int, len(artifacts))
	for _, entry := range entries {
		for _, component := range entry.Metadata {
			artifact, ok := artifacts[component.ArtifactID]
			if !ok || artifact.EntryID != entry.EntryID || artifact.Permission != catalogv1.PermissionMetadata {
				return fmt.Errorf("metadata component %q has invalid artifact reference", component.ComponentID)
			}
			references[component.ArtifactID]++
		}
		for _, component := range entry.Routing {
			if component.ArtifactID == "" {
				continue
			}
			artifact, ok := artifacts[component.ArtifactID]
			if !ok || artifact.EntryID != entry.EntryID || artifact.Permission != catalogv1.PermissionRoutingData {
				return fmt.Errorf("routing component %q has invalid artifact reference", component.ComponentID)
			}
			references[component.ArtifactID]++
		}
		for _, component := range entry.Detection {
			seen := make(map[string]struct{}, len(component.ArtifactIDs))
			for _, artifactID := range component.ArtifactIDs {
				if _, duplicate := seen[artifactID]; duplicate {
					return fmt.Errorf("detection component %q repeats artifact %q", component.ComponentID, artifactID)
				}
				seen[artifactID] = struct{}{}
				artifact, ok := artifacts[artifactID]
				if !ok || artifact.EntryID != entry.EntryID ||
					(artifact.Permission != catalogv1.PermissionDetectionData && artifact.Permission != catalogv1.PermissionExecutable) {
					return fmt.Errorf("detection component %q has invalid artifact reference", component.ComponentID)
				}
				references[artifactID]++
			}
		}
	}
	for artifactID := range artifacts {
		if references[artifactID] == 0 {
			return fmt.Errorf("artifact %q is unreferenced", artifactID)
		}
	}
	return nil
}

func validateRevocations(source catalogv1.Source) error {
	seen := make(map[string]struct{}, len(source.Revocations))
	for _, revocation := range source.Revocations {
		if !validID(revocation.RevocationID) || revocation.Version == 0 || revocation.Version > source.Version || strings.TrimSpace(revocation.Reason) == "" {
			return fmt.Errorf("invalid revocation")
		}
		if _, duplicate := seen[revocation.RevocationID]; duplicate {
			return fmt.Errorf("duplicate revocation stable ID %q", revocation.RevocationID)
		}
		seen[revocation.RevocationID] = struct{}{}
		switch revocation.Kind {
		case "entry", "artifact", "engine", "key":
			if !validID(revocation.TargetID) {
				return fmt.Errorf("invalid revocation target")
			}
		case "digest":
			if !digest.MatchString(revocation.TargetID) {
				return fmt.Errorf("invalid digest revocation target")
			}
		default:
			return fmt.Errorf("invalid revocation kind %q", revocation.Kind)
		}
	}
	return nil
}

func validID(value string) bool {
	return stableID.MatchString(value)
}

func validSlot(value string) bool {
	return value == "availability" || value == "serviceRegion" || value == "cdnRegion"
}
