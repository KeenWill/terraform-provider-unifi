// Package integration implements read-only discovery through the documented local
// Network API. Its models must not be used as replacement write payloads.
package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	requestTimeout   = 30 * time.Second
	maxResponseBytes = 8 << 20
	pageSize         = 200
	maxPages         = 1000
	readAttempts     = 3
)

// HTTPError deliberately excludes response bodies, URLs and authentication data.
// A 404 means endpoint/object unavailable, never permission to discard state.
type HTTPError struct{ StatusCode int }

func (e *HTTPError) Error() string {
	return fmt.Sprintf("Network Integration API returned HTTP %d", e.StatusCode)
}

// Client never follows redirects or falls back to legacy/session authentication.
type Client struct {
	baseURL    url.URL
	apiKey     string
	httpClient *http.Client
}

// New creates a local-console client without making requests. The supplied
// transport can provide a custom CA or the provider's explicit insecure option.
func New(consoleURL, apiKey string, transport http.RoundTripper) (*Client, error) {
	base, err := url.Parse(consoleURL)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || (base.Path != "" && base.Path != "/") {
		return nil, errors.New("integration API requires an HTTPS console origin without credentials, path, query or fragment")
	}
	if strings.TrimSpace(apiKey) == "" {
		return nil, errors.New("integration API requires an API key")
	}
	base.Path = "/proxy/network/integration/v1"
	return &Client{baseURL: *base, apiKey: apiKey, httpClient: &http.Client{Transport: transport, Timeout: requestTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (c *Client) get(ctx context.Context, path string, query url.Values, result any) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	target := c.baseURL
	target.Path += path
	target.RawQuery = query.Encode()
	for attempt := range readAttempts {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
		if err != nil {
			return errors.New("cannot construct Integration API request")
		}
		request.Header.Set("X-API-KEY", c.apiKey)
		request.Header.Set("Accept", "application/json")
		response, err := c.httpClient.Do(request)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// Transport errors can include proxy credentials or URLs; do not expose them.
			return errors.New("integration API transport failed")
		}
		payload, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
		_ = response.Body.Close()
		if readErr != nil {
			return errors.New("cannot read Integration API response")
		}
		if len(payload) > maxResponseBytes {
			return errors.New("integration API response exceeds size limit")
		}
		if (response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= http.StatusInternalServerError) && attempt+1 < readAttempts {
			delay := time.Duration(attempt+1) * 100 * time.Millisecond
			if seconds, err := strconv.Atoi(response.Header.Get("Retry-After")); err == nil && seconds > 0 {
				if seconds > 5 {
					seconds = 5
				}
				delay = time.Duration(seconds) * time.Second
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
			continue
		}
		if response.StatusCode != http.StatusOK {
			return &HTTPError{StatusCode: response.StatusCode}
		}
		if len(payload) == 0 || strings.TrimSpace(string(payload)) == "null" {
			return errors.New("empty Integration API response")
		}
		if err := json.Unmarshal(payload, result); err != nil {
			return errors.New("malformed Integration API response")
		}
		return nil
	}
	return errors.New("integration API read attempts exhausted")
}

type page[T any] struct {
	Offset     *int `json:"offset"`
	Limit      *int `json:"limit"`
	Count      *int `json:"count"`
	TotalCount *int `json:"totalCount"`
	Data       []T  `json:"data"`
}

func list[T any](ctx context.Context, client *Client, path string) ([]T, error) {
	result := []T{}
	offset := 0
	total := -1
	for range maxPages {
		var response page[T]
		err := client.get(ctx, path, url.Values{"offset": {strconv.Itoa(offset)}, "limit": {strconv.Itoa(pageSize)}}, &response)
		if err != nil {
			return nil, err
		}
		if response.Offset == nil || response.Limit == nil || response.Count == nil || response.TotalCount == nil || response.Data == nil {
			return nil, errors.New("incomplete Integration API page")
		}
		if *response.Offset != offset || *response.Count != len(response.Data) || *response.Limit <= 0 || *response.Count > *response.Limit || *response.TotalCount < offset+*response.Count {
			return nil, errors.New("inconsistent Integration API page")
		}
		if total >= 0 && total != *response.TotalCount {
			return nil, errors.New("integration API inventory changed during pagination; retry discovery")
		}
		total = *response.TotalCount
		result = append(result, response.Data...)
		offset += *response.Count
		if offset == total {
			return result, nil
		}
		if *response.Count == 0 {
			return nil, errors.New("integration API pagination made no progress")
		}
	}
	return nil, errors.New("integration API page limit exceeded")
}

func segment(value string) error {
	if strings.TrimSpace(value) == "" || value == "." || value == ".." || strings.ContainsAny(value, "/\\?#%\x00\r\n") {
		return errors.New("invalid Integration API identity segment")
	}
	return nil
}
