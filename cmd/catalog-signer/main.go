package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

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
		return fmt.Errorf("usage: catalog-signer inspect|sign")
	}
	switch args[0] {
	case "inspect":
		flags := flag.NewFlagSet("inspect", flag.ContinueOnError)
		flags.SetOutput(stderr)
		candidate := flags.String("candidate", "", "candidate directory")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if *candidate == "" || flags.NArg() != 0 {
			return fmt.Errorf("inspect requires --candidate DIR and no positional arguments")
		}
		inspection, err := signing.Inspect(*candidate)
		if err != nil {
			return err
		}
		return json.NewEncoder(stdout).Encode(inspection)
	case "sign":
		flags := flag.NewFlagSet("sign", flag.ContinueOnError)
		flags.SetOutput(stderr)
		candidate := flags.String("candidate", "", "candidate directory")
		expectedRequestDigest := flags.String("expect-request-digest", "", "request digest confirmed during inspect")
		encryptedKey := flags.String("encrypted-key", "", "encrypted signing key file")
		passphraseFile := flags.String("passphrase-file", "", "owner-only passphrase file")
		output := flags.String("output", "", "new signature fragment file")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if *candidate == "" || *expectedRequestDigest == "" || *encryptedKey == "" || *passphraseFile == "" || *output == "" || flags.NArg() != 0 {
			return fmt.Errorf("sign requires --candidate DIR --expect-request-digest SHA256 --encrypted-key FILE --passphrase-file FILE --output FILE")
		}
		prepared, err := signing.Prepare(*candidate)
		if err != nil {
			return fmt.Errorf("candidate preflight: %w", err)
		}
		if err := validateOutputPath(*candidate, *output); err != nil {
			return err
		}
		if prepared.Inspection().RequestDigest != *expectedRequestDigest {
			return fmt.Errorf("candidate request digest does not match --expect-request-digest")
		}
		passphrase, err := signing.ReadPassphraseFile(*passphraseFile)
		if err != nil {
			return fmt.Errorf("read passphrase: %w", err)
		}
		defer clearBytes(passphrase)
		provider, err := signing.OpenEncryptedFileProvider(*encryptedKey, passphrase)
		if err != nil {
			return err
		}
		defer provider.Close()
		fragment, err := prepared.Sign(provider)
		if err != nil {
			return err
		}
		content, err := signing.EncodeFragment(fragment)
		if err != nil {
			return err
		}
		return writeNewAtomic(*output, content)
	default:
		return fmt.Errorf("command %q is not allowlisted", args[0])
	}
}

func validateOutputPath(candidateRoot, outputPath string) error {
	candidateAbsolute, err := filepath.Abs(candidateRoot)
	if err != nil {
		return fmt.Errorf("resolve candidate path: %w", err)
	}
	candidateResolved, err := filepath.EvalSymlinks(candidateAbsolute)
	if err != nil {
		return fmt.Errorf("resolve candidate path: %w", err)
	}
	outputAbsolute, err := filepath.Abs(outputPath)
	if err != nil {
		return fmt.Errorf("resolve output path: %w", err)
	}
	parentAbsolute := filepath.Dir(outputAbsolute)
	parentResolved, err := filepath.EvalSymlinks(parentAbsolute)
	if err != nil {
		return fmt.Errorf("resolve output directory: %w", err)
	}
	if parentResolved != parentAbsolute {
		return fmt.Errorf("output directory path must not contain symlinks")
	}
	resolvedOutput := filepath.Join(parentResolved, filepath.Base(outputAbsolute))
	relative, err := filepath.Rel(candidateResolved, resolvedOutput)
	if err != nil {
		return fmt.Errorf("compare candidate and output paths: %w", err)
	}
	if relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))) {
		return fmt.Errorf("fragment output must be outside candidate directory")
	}
	if _, err := os.Lstat(resolvedOutput); err == nil {
		return fmt.Errorf("output already exists: %s", outputPath)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect output: %w", err)
	}
	return nil
}

func writeNewAtomic(outputPath string, content []byte) error {
	if outputPath == "" {
		return fmt.Errorf("output path is required")
	}
	if _, err := os.Lstat(outputPath); err == nil {
		return fmt.Errorf("output already exists: %s", outputPath)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect output: %w", err)
	}
	parent := filepath.Dir(outputPath)
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf("inspect output directory: %w", err)
	}
	if !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("output directory must be a real directory")
	}
	temporary, err := os.CreateTemp(parent, ".catalog-fragment-*")
	if err != nil {
		return fmt.Errorf("create temporary fragment: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o644); err != nil {
		temporary.Close()
		return fmt.Errorf("set fragment mode: %w", err)
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return fmt.Errorf("write fragment: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync fragment: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close fragment: %w", err)
	}
	if err := os.Link(temporaryPath, outputPath); err != nil {
		return fmt.Errorf("publish fragment without overwrite: %w", err)
	}
	return nil
}

func clearBytes(content []byte) {
	for index := range content {
		content[index] = 0
	}
}
