package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"

	"github.com/holandyoung/unlock-catalog/internal/repository"
)

func runVerifyOrigin(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("verify-origin", flag.ContinueOnError)
	flags.SetOutput(stderr)
	repositoryRoot := flags.String("repository", ".", "protected Catalog repository checkout")
	baseURL := flags.String("base-url", "", "canonical HTTPS URL for catalog/sources/")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *baseURL == "" {
		return fmt.Errorf("verify-origin requires --base-url URL and no positional arguments")
	}
	report, err := repository.VerifyOrigin(context.Background(), repository.OriginOptions{
		RepositoryRoot: *repositoryRoot,
		BaseURL:        *baseURL,
		Client:         http.DefaultClient,
	})
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(report)
}
