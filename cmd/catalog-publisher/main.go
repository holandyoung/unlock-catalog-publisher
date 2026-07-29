package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/holandyoung/unlock-catalog/internal/cohort"
	"github.com/holandyoung/unlock-catalog/internal/policy"
)

func main() {
	if err := run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: catalog-publisher candidate|materialize|verify-release")
	}
	switch args[0] {
	case "candidate":
		return runCandidate(args[1:], getenv, stdout, stderr)
	case "materialize":
		return runMaterialize(args[1:], stdout, stderr)
	case "verify-release":
		return runVerifyRelease(args[1:], stdout, stderr)
	default:
		return fmt.Errorf("usage: catalog-publisher candidate|materialize|verify-release")
	}
}

func runCandidate(args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("candidate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	sourcesRoot := flags.String("sources", "catalog/definitions", "declarative source root")
	outputRoot := flags.String("output", "", "new candidate output directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *outputRoot == "" {
		return fmt.Errorf("candidate requires --output DIR and no positional arguments")
	}
	epoch, err := sourceDateEpoch(getenv)
	if err != nil {
		return err
	}
	return buildAll(*sourcesRoot, *outputRoot, epoch, stdout)
}

func sourceDateEpoch(getenv func(string) string) (time.Time, error) {
	raw := getenv("SOURCE_DATE_EPOCH")
	if raw == "" {
		return time.Time{}, fmt.Errorf("SOURCE_DATE_EPOCH is required")
	}
	seconds, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || seconds < 0 || strconv.FormatInt(seconds, 10) != raw {
		return time.Time{}, fmt.Errorf("SOURCE_DATE_EPOCH must be a non-negative canonical base-10 integer")
	}
	return time.Unix(seconds, 0).UTC(), nil
}

func buildAll(sourcesRoot, outputRoot string, epoch time.Time, stdout io.Writer) error {
	if _, err := os.Lstat(outputRoot); err == nil {
		return fmt.Errorf("candidate output already exists: %s", outputRoot)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect candidate output: %w", err)
	}
	paths, err := filepath.Glob(filepath.Join(sourcesRoot, "*", "source.yaml"))
	if err != nil {
		return fmt.Errorf("discover sources: %w", err)
	}
	sort.Strings(paths)
	want := map[string]struct{}{policy.DataSourceID: {}, policy.ExecSourceID: {}}
	if len(paths) != len(want) {
		return fmt.Errorf("publisher requires exactly the data and executable source roots")
	}
	for _, path := range paths {
		id := filepath.Base(filepath.Dir(path))
		if _, ok := want[id]; !ok {
			return fmt.Errorf("unexpected source root %q", id)
		}
		delete(want, id)
	}
	if len(want) != 0 {
		return fmt.Errorf("publisher source roots are incomplete")
	}

	parent := filepath.Dir(outputRoot)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("create candidate parent: %w", err)
	}
	staging, err := os.MkdirTemp(parent, ".catalog-candidate-*")
	if err != nil {
		return fmt.Errorf("create candidate staging root: %w", err)
	}
	defer os.RemoveAll(staging)
	for _, path := range paths {
		candidate, err := cohort.BuildCandidate(path, staging, epoch)
		if err != nil {
			return fmt.Errorf("build %s: %w", filepath.Base(filepath.Dir(path)), err)
		}
		fmt.Fprintf(stdout, "%s %s\n", candidate.SourceID, candidate.PayloadSHA256)
	}
	if err := os.Rename(staging, outputRoot); err != nil {
		return fmt.Errorf("publish candidate set: %w", err)
	}
	return nil
}
