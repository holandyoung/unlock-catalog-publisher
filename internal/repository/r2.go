package repository

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

const MaxReadbackBytes = 256 << 20

var r2BucketPattern = regexp.MustCompile("^[a-z0-9](?:[a-z0-9.-]{1,61}[a-z0-9])$")

type R2Config struct {
	Endpoint        string
	Bucket          string
	AccessKeyID     string
	SecretAccessKey string
	HTTPClient      *http.Client
}

type R2Store struct {
	client *s3.Client
	bucket string
}

func NewR2Store(ctx context.Context, options R2Config) (*R2Store, error) {
	endpoint, err := validateR2Config(options)
	if err != nil {
		return nil, err
	}
	httpClient := options.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	clientCopy := *httpClient
	transport := httpClient.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	clientCopy.Transport = acceptIdentityTransport{base: transport}
	configuration, err := awsconfig.LoadDefaultConfig(
		ctx,
		awsconfig.WithRegion("auto"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			options.AccessKeyID, options.SecretAccessKey, "",
		)),
		awsconfig.WithHTTPClient(&clientCopy),
	)
	if err != nil {
		return nil, fmt.Errorf("load R2 client config: %w", err)
	}
	configuration.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
	configuration.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
	client := s3.NewFromConfig(configuration, func(s3Options *s3.Options) {
		s3Options.BaseEndpoint = aws.String(endpoint)
		s3Options.UsePathStyle = true
	})
	return &R2Store{client: client, bucket: options.Bucket}, nil
}

func (store *R2Store) PutObject(ctx context.Context, request PutRequest) (PutResult, error) {
	if store == nil || store.client == nil {
		return PutResult{}, fmt.Errorf("R2 store is required")
	}
	if request.Key == "" || len(request.Body) == 0 || request.ContentType == "" ||
		request.CacheControl == "" || request.ContentMD5 == "" || request.SHA256 == "" {
		return PutResult{}, fmt.Errorf("complete R2 put request is required")
	}
	if request.ContentEncoding != "" {
		return PutResult{}, fmt.Errorf("R2 uploads must use identity content encoding")
	}
	if request.Condition.IfNoneMatch == (request.Condition.IfMatch != "") {
		return PutResult{}, fmt.Errorf("exactly one R2 put condition is required")
	}
	input := &s3.PutObjectInput{
		Bucket: aws.String(store.bucket), Key: aws.String(request.Key),
		Body: bytes.NewReader(request.Body), ContentLength: aws.Int64(int64(len(request.Body))),
		ContentMD5: aws.String(request.ContentMD5), ContentType: aws.String(request.ContentType),
		CacheControl: aws.String(request.CacheControl), Metadata: map[string]string{"sha256": request.SHA256},
	}
	if request.Condition.IfNoneMatch {
		input.IfNoneMatch = aws.String("*")
	} else {
		input.IfMatch = aws.String(request.Condition.IfMatch)
	}
	output, err := store.client.PutObject(ctx, input)
	if err != nil {
		return PutResult{}, mapR2Error(err)
	}
	return PutResult{ETag: aws.ToString(output.ETag)}, nil
}

func (store *R2Store) HeadObject(ctx context.Context, key string) (Metadata, error) {
	if store == nil || store.client == nil || key == "" {
		return Metadata{}, fmt.Errorf("R2 store and key are required")
	}
	output, err := store.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(store.bucket), Key: aws.String(key),
	})
	if err != nil {
		return Metadata{}, mapR2Error(err)
	}
	return Metadata{
		ETag: aws.ToString(output.ETag), Length: aws.ToInt64(output.ContentLength),
		SHA256: output.Metadata["sha256"], ContentType: aws.ToString(output.ContentType),
		CacheControl: aws.ToString(output.CacheControl), ContentEncoding: aws.ToString(output.ContentEncoding),
		AcceptRanges: aws.ToString(output.AcceptRanges),
	}, nil
}

func (store *R2Store) GetObject(ctx context.Context, request GetRequest) (GetResult, error) {
	if store == nil || store.client == nil || request.Key == "" {
		return GetResult{}, fmt.Errorf("R2 store and key are required")
	}
	input := &s3.GetObjectInput{Bucket: aws.String(store.bucket), Key: aws.String(request.Key)}
	if request.Range != "" {
		input.Range = aws.String(request.Range)
	}
	output, err := store.client.GetObject(ctx, input)
	if err != nil {
		return GetResult{}, mapR2Error(err)
	}
	content, readErr := io.ReadAll(io.LimitReader(output.Body, MaxReadbackBytes+1))
	closeErr := output.Body.Close()
	if readErr != nil {
		return GetResult{}, fmt.Errorf("read R2 object %q: %w", request.Key, readErr)
	}
	if closeErr != nil {
		return GetResult{}, fmt.Errorf("close R2 object %q: %w", request.Key, closeErr)
	}
	if len(content) > MaxReadbackBytes {
		return GetResult{}, fmt.Errorf("R2 object %q exceeds readback limit", request.Key)
	}
	return GetResult{
		Metadata: Metadata{
			ETag: aws.ToString(output.ETag), Length: aws.ToInt64(output.ContentLength),
			SHA256: output.Metadata["sha256"], ContentType: aws.ToString(output.ContentType),
			CacheControl: aws.ToString(output.CacheControl), ContentEncoding: aws.ToString(output.ContentEncoding),
			AcceptRanges: aws.ToString(output.AcceptRanges),
		},
		Body: content, ContentRange: aws.ToString(output.ContentRange),
	}, nil
}

func validateR2Config(options R2Config) (string, error) {
	endpoint, err := url.Parse(options.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil ||
		endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return "", fmt.Errorf("R2 endpoint must be an origin-only HTTPS URL")
	}
	if !r2BucketPattern.MatchString(options.Bucket) {
		return "", fmt.Errorf("R2 bucket is invalid")
	}
	if strings.TrimSpace(options.AccessKeyID) == "" || strings.TrimSpace(options.SecretAccessKey) == "" {
		return "", fmt.Errorf("R2 deploy credential is required")
	}
	return strings.TrimSuffix(options.Endpoint, "/"), nil
}

func mapR2Error(err error) error {
	var apiError smithy.APIError
	if errors.As(err, &apiError) {
		switch apiError.ErrorCode() {
		case "PreconditionFailed", "ConditionalRequestConflict":
			return fmt.Errorf("%w: %v", ErrPreconditionFailed, err)
		case "NoSuchKey", "NotFound", "NoSuchBucket":
			return fmt.Errorf("%w: %v", ErrNotFound, err)
		}
	}
	var responseError *smithyhttp.ResponseError
	if errors.As(err, &responseError) {
		switch responseError.HTTPStatusCode() {
		case http.StatusPreconditionFailed, http.StatusConflict:
			return fmt.Errorf("%w: %v", ErrPreconditionFailed, err)
		case http.StatusNotFound:
			return fmt.Errorf("%w: %v", ErrNotFound, err)
		}
	}
	return err
}

type acceptIdentityTransport struct {
	base http.RoundTripper
}

func (transport acceptIdentityTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.Header = request.Header.Clone()
	clone.Header.Set("Accept-Encoding", "identity")
	return transport.base.RoundTrip(clone)
}
