package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/holandyoung/unlock-catalog-publisher/internal/assemble"
	"github.com/holandyoung/unlock-catalog-publisher/internal/catalogv1"
	"github.com/holandyoung/unlock-catalog-publisher/internal/signing"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: catalog-assembler root|release")
	}
	switch args[0] {
	case "root":
		return runRoot(args[1:], stdout, stderr)
	case "release":
		return runRelease(args[1:], stdout, stderr)
	default:
		return fmt.Errorf("command %q is not allowlisted", args[0])
	}
}

func runRoot(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("root", flag.ContinueOnError)
	flags.SetOutput(stderr)
	currentPath := flags.String("current-root", "", "current public root JSON")
	nextPath := flags.String("next-root", "", "next public root JSON")
	nowValue := flags.String("now", "", "reviewed UTC RFC3339 time")
	output := flags.String("output", "", "new signed root JSON")
	var fragmentPaths stringList
	flags.Var(&fragmentPaths, "fragment", "offline root signature fragment (repeat exactly as needed)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *currentPath == "" || *nextPath == "" || *nowValue == "" || *output == "" || len(fragmentPaths) == 0 || flags.NArg() != 0 {
		return fmt.Errorf("root requires --current-root FILE --next-root FILE --now RFC3339 --fragment FILE... --output FILE")
	}
	var current, next assemble.TrustRoot
	if err := decodeFile(*currentPath, &current); err != nil {
		return fmt.Errorf("current root: %w", err)
	}
	if err := decodeFile(*nextPath, &next); err != nil {
		return fmt.Errorf("next root: %w", err)
	}
	now, err := time.Parse(time.RFC3339, *nowValue)
	if err != nil || !now.Equal(now.UTC()) {
		return fmt.Errorf("--now must be a UTC RFC3339 value")
	}
	fragments, err := readFragments(fragmentPaths)
	if err != nil {
		return err
	}
	signed, err := assemble.AssembleSignedRoot(current, next, fragments, now)
	if err != nil {
		return err
	}
	content, err := json.Marshal(signed)
	if err != nil {
		return err
	}
	if err := writeNew(*output, content); err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(map[string]any{"version": signed.Signed.Version, "output": *output})
}

func runRelease(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("release", flag.ContinueOnError)
	flags.SetOutput(stderr)
	candidate := flags.String("candidate", "", "validated candidate directory")
	currentPath := flags.String("current-root", "", "current public root JSON")
	signedRootPath := flags.String("signed-root", "", "threshold-signed bridge root JSON")
	sourceID := flags.String("source-id", "", "expected source identity")
	permissionsValue := flags.String("permissions", "", "comma-separated exact permission set")
	priorPath := flags.String("prior-manifest", "", "optional prior signed manifest JSON")
	nowValue := flags.String("now", "", "reviewed UTC RFC3339 time")
	output := flags.String("output", "", "new release directory")
	var fragmentPaths stringList
	flags.Var(&fragmentPaths, "fragment", "offline manifest signature fragment (repeat exactly as needed)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *candidate == "" || *currentPath == "" || *signedRootPath == "" || *sourceID == "" || *permissionsValue == "" || *nowValue == "" || *output == "" || len(fragmentPaths) == 0 || flags.NArg() != 0 {
		return fmt.Errorf("release requires candidate, roots, source ID, permissions, time, fragments, and output")
	}
	var current assemble.TrustRoot
	if err := decodeFile(*currentPath, &current); err != nil {
		return err
	}
	var signedRoot assemble.SignedRoot
	if err := decodeFile(*signedRootPath, &signedRoot); err != nil {
		return err
	}
	fragments, err := readFragments(fragmentPaths)
	if err != nil {
		return err
	}
	now, err := time.Parse(time.RFC3339, *nowValue)
	if err != nil || !now.Equal(now.UTC()) {
		return fmt.Errorf("--now must be a UTC RFC3339 value")
	}
	permissions, err := parsePermissions(*permissionsValue)
	if err != nil {
		return err
	}
	var prior []catalogv1.Revocation
	if *priorPath != "" {
		var manifest assemble.SignedManifest
		if err := decodeFile(*priorPath, &manifest); err != nil {
			return err
		}
		prior = manifest.Signed.Revocations
	}
	release, err := assemble.Assemble(assemble.Options{
		CandidateDir: *candidate, OutputDir: *output, ExpectedSourceID: *sourceID,
		GrantedPermissions: permissions, CurrentRoot: current, PublishedRoot: signedRoot,
		PriorRevocations: prior, Now: now,
	}, fragments)
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(map[string]any{"directory": release.Directory, "package": release.PackagePath})
}

type stringList []string

func (values *stringList) String() string { return strings.Join(*values, ",") }
func (values *stringList) Set(value string) error {
	if value == "" {
		return fmt.Errorf("fragment path is empty")
	}
	*values = append(*values, value)
	return nil
}

func readFragments(paths []string) ([]signing.Fragment, error) {
	fragments := make([]signing.Fragment, 0, len(paths))
	for _, path := range paths {
		var fragment signing.Fragment
		if err := decodeFile(path, &fragment); err != nil {
			return nil, fmt.Errorf("fragment %q: %w", path, err)
		}
		fragments = append(fragments, fragment)
	}
	return fragments, nil
}

func parsePermissions(value string) ([]catalogv1.Permission, error) {
	parts := strings.Split(value, ",")
	permissions := make([]catalogv1.Permission, 0, len(parts))
	seen := map[catalogv1.Permission]struct{}{}
	for _, part := range parts {
		permission := catalogv1.Permission(strings.TrimSpace(part))
		switch permission {
		case catalogv1.PermissionMetadata, catalogv1.PermissionDetectionData, catalogv1.PermissionRoutingData, catalogv1.PermissionExecutable:
		default:
			return nil, fmt.Errorf("unknown permission %q", part)
		}
		if _, duplicate := seen[permission]; duplicate {
			return nil, fmt.Errorf("duplicate permission %q", permission)
		}
		seen[permission] = struct{}{}
		permissions = append(permissions, permission)
	}
	return permissions, nil
}

func decodeFile(path string, target any) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return fmt.Errorf("trailing JSON data: %w", err)
	}
	return nil
}

func writeNew(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}
