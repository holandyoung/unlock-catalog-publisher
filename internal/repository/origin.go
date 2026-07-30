package repository

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const originRequestTimeout = 15 * time.Second

type OriginOptions struct {
	RepositoryRoot string
	BaseURL        string
	Client         *http.Client
}

type OriginReport struct {
	BaseURL     string `json:"baseUrl"`
	SourceCount int    `json:"sourceCount"`
	FileCount   int    `json:"fileCount"`
	FileBytes   int64  `json:"fileBytes"`
}

// VerifyOrigin compares an anonymous HTTPS origin with the protected local
// release tree. It deliberately performs no signature operation and no write.
func VerifyOrigin(ctx context.Context, options OriginOptions) (OriginReport, error) {
	if ctx == nil {
		return OriginReport{}, fmt.Errorf("origin context is required")
	}
	if err := validateRepositoryRoot(options.RepositoryRoot); err != nil {
		return OriginReport{}, fmt.Errorf("repository root: %w", err)
	}
	base, err := canonicalOriginBaseURL(options.BaseURL)
	if err != nil {
		return OriginReport{}, err
	}
	sources, err := readRepositorySources(options.RepositoryRoot)
	if err != nil {
		return OriginReport{}, fmt.Errorf("read protected release tree: %w", err)
	}
	targets := make(map[string][]byte)
	for sourceID, files := range sources {
		for relative, file := range files {
			targets[path.Join(sourceID, relative)] = file.body
		}
	}
	if len(sources) == 0 {
		readmePath := filepath.Join(options.RepositoryRoot, filepath.FromSlash(ReleasePrefix), "README.md")
		info, err := os.Lstat(readmePath)
		if err != nil {
			return OriginReport{}, fmt.Errorf("read empty-origin sentinel: %w", err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o644 {
			return OriginReport{}, fmt.Errorf("empty-origin sentinel must be a mode 0644 regular file")
		}
		content, err := os.ReadFile(readmePath)
		if err != nil {
			return OriginReport{}, err
		}
		targets["README.md"] = content
	}

	client := originClient(options.Client)
	paths := make([]string, 0, len(targets))
	for relative := range targets {
		paths = append(paths, relative)
	}
	sort.Strings(paths)
	report := OriginReport{BaseURL: base.String(), SourceCount: len(sources)}
	for _, relative := range paths {
		if err := compareOriginFile(ctx, client, base, relative, targets[relative]); err != nil {
			return OriginReport{}, err
		}
		report.FileCount++
		report.FileBytes += int64(len(targets[relative]))
	}
	return report, nil
}

func canonicalOriginBaseURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse origin base URL: %w", err)
	}
	if raw == "" || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" || !strings.HasSuffix(parsed.Path, "/") {
		return nil, fmt.Errorf("origin BaseURL must be canonical anonymous HTTPS with a trailing slash")
	}
	if parsed.Path != "/" && path.Clean(parsed.Path)+"/" != parsed.Path {
		return nil, fmt.Errorf("origin BaseURL path is not canonical")
	}
	if parsed.String() != raw {
		return nil, fmt.Errorf("origin BaseURL is not canonical")
	}
	return parsed, nil
}

func originClient(configured *http.Client) *http.Client {
	if configured == nil {
		configured = http.DefaultClient
	}
	client := *configured
	client.Jar = nil
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return fmt.Errorf("origin redirects are forbidden")
	}
	if client.Timeout == 0 || client.Timeout > originRequestTimeout {
		client.Timeout = originRequestTimeout
	}
	return &client
}

func compareOriginFile(ctx context.Context, client *http.Client, base *url.URL, relative string, expected []byte) error {
	if relative == "" || path.IsAbs(relative) || path.Clean(relative) != relative || strings.Contains(relative, "\\") || strings.HasPrefix(relative, "../") {
		return fmt.Errorf("unsafe origin path %q", relative)
	}
	target := *base
	target.Path = base.Path + relative
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("Accept", "application/octet-stream, application/json;q=0.9, text/plain;q=0.8")
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("fetch origin path %q: %w", relative, err)
	}
	defer response.Body.Close()
	if response.Request == nil || response.Request.URL.String() != target.String() {
		return fmt.Errorf("origin path %q changed request URL", relative)
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("origin path %q returned HTTP %d", relative, response.StatusCode)
	}
	encoding := response.Header.Get("Content-Encoding")
	if encoding != "" && !strings.EqualFold(encoding, "identity") {
		return fmt.Errorf("origin path %q returned content encoding %q", relative, encoding)
	}
	if response.ContentLength >= 0 && response.ContentLength != int64(len(expected)) {
		return fmt.Errorf("origin path %q content length differs", relative)
	}
	if len(expected) == 0 || len(expected) > MaxReleaseFileBytes {
		return fmt.Errorf("origin path %q expected bytes are outside limits", relative)
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, int64(MaxReleaseFileBytes)+1))
	if err != nil {
		return fmt.Errorf("read origin path %q: %w", relative, err)
	}
	if len(content) > MaxReleaseFileBytes || !bytes.Equal(content, expected) {
		return fmt.Errorf("origin path %q differs from protected tree", relative)
	}
	return nil
}
