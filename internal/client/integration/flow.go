package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// FlowPolicy retains the full document for preservation checks, never as a write payload.
type FlowPolicy struct {
	ID       ObjectID
	Enabled  bool
	Document map[string]any
}

func flowPath(site SiteID, id ObjectID) (string, error) {
	if segment(string(site)) != nil || segment(string(id)) != nil {
		return "", errors.New("invalid official site or policy ID")
	}
	return "/sites/" + string(site) + "/firewall/policies/" + string(id), nil
}

func (c *Client) FlowPolicy(ctx context.Context, site SiteID, id ObjectID) (*FlowPolicy, error) {
	path, err := flowPath(site, id)
	if err != nil {
		return nil, err
	}
	var document map[string]any
	if err = c.get(ctx, path, nil, &document); err != nil {
		return nil, err
	}
	enabled, ok := document["reportFlowEnabled"].(bool)
	metadata, _ := document["metadata"].(map[string]any)
	if document["id"] != string(id) || !ok || metadata["origin"] != "USER_DEFINED" {
		return nil, errors.New("flow reporting requires a user-defined policy with an explicit reportFlowEnabled field")
	}
	return &FlowPolicy{ID: id, Enabled: enabled, Document: document}, nil
}

// SetFlowReporting reads current state, PATCHes exactly one declared field, and
// verifies it. Mutations are never retried automatically or redirected.
func (c *Client) SetFlowReporting(ctx context.Context, site SiteID, id ObjectID, enabled bool) (*FlowPolicy, error) {
	info, err := c.Info(ctx)
	if err != nil {
		return nil, err
	}
	if info.ApplicationVersion != "11.0.99" {
		return nil, errors.New("flow reporting writes are qualified only for Network 11.0.99")
	}
	before, err := c.FlowPolicy(ctx, site, id)
	if err != nil {
		return nil, err
	}
	if before.Enabled == enabled {
		return before, nil
	}
	path, _ := flowPath(site, id)
	target := c.baseURL
	target.Path += path
	body, _ := json.Marshal(map[string]bool{"reportFlowEnabled": enabled})
	request, err := http.NewRequestWithContext(ctx, http.MethodPatch, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("cannot construct flow reporting request")
	}
	request.Header.Set("X-API-KEY", c.apiKey)
	request.Header.Set("Content-Type", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, errors.New("flow reporting transport failed; refresh before retrying")
	}
	_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes+1))
	response.Body.Close()
	if readErr != nil {
		return nil, errors.New("cannot read flow reporting response; refresh before retrying")
	}
	if response.StatusCode != http.StatusOK {
		return nil, &HTTPError{StatusCode: response.StatusCode}
	}
	after, err := c.FlowPolicy(ctx, site, id)
	if err != nil {
		return nil, err
	}
	if after.Enabled != enabled {
		return nil, errors.New("controller did not retain declared flow reporting value")
	}
	return after, nil
}
