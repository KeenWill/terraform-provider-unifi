package legacy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
)

const maxUserResponseBytes = 8 << 20

var userResponsePath = regexp.MustCompile(`/s/[^/]+/(?:(?:rest|stat|group)/user(?:/[^/]+)?|cmd/stamgr)$|/site/[^/]+/station/[^/]+/fingerprint_override$`)

// UserCompatibilityTransport normalizes the one known Network 11 field-type
// change before the legacy SDK decodes it. It never modifies requests or other
// numeric-looking strings (IDs in particular are opaque).
type UserCompatibilityTransport struct{ Next http.RoundTripper }

func (transport *UserCompatibilityTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := transport.Next.RoundTrip(request)
	if err != nil || response.StatusCode != http.StatusOK || !userResponsePath.MatchString(request.URL.Path) {
		return response, err
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxUserResponseBytes+1))
	_ = response.Body.Close()
	if err != nil {
		return nil, errors.New("cannot read legacy client response")
	}
	if len(payload) > maxUserResponseBytes {
		return nil, errors.New("legacy client response exceeds size limit")
	}
	normalized, err := normalizeUserResponse(payload)
	if err != nil {
		return nil, err
	}
	response.Body = io.NopCloser(bytes.NewReader(normalized))
	response.ContentLength = int64(len(normalized))
	response.Header.Set("Content-Length", strconv.Itoa(len(normalized)))
	return response, nil
}

func normalizeUserResponse(payload []byte) ([]byte, error) {
	var envelope map[string]json.RawMessage
	if json.Unmarshal(payload, &envelope) != nil || envelope == nil {
		return nil, errors.New("malformed legacy client response")
	}
	if err := normalizeUserObject(envelope); err != nil {
		return nil, err
	}
	return json.Marshal(envelope)
}

func normalizeUserObject(object map[string]json.RawMessage) error {
	if raw, exists := object["dev_id_override"]; exists && len(raw) > 0 && raw[0] == '"' {
		var value string
		if json.Unmarshal(raw, &value) != nil {
			return errors.New("malformed legacy client fingerprint")
		}
		// Empty/null both mean no override, matching the SDK's existing zero value.
		if value == "" {
			value = "0"
		}
		number, err := strconv.ParseInt(value, 10, 32)
		if err != nil || number < 0 {
			return errors.New("legacy client fingerprint must be a nonnegative 32-bit integer")
		}
		object["dev_id_override"] = json.RawMessage(strconv.FormatInt(number, 10))
	}
	if raw, exists := object["data"]; exists && string(raw) != "null" {
		var children []map[string]json.RawMessage
		if json.Unmarshal(raw, &children) != nil {
			return errors.New("malformed legacy client data envelope")
		}
		for _, child := range children {
			if err := normalizeUserObject(child); err != nil {
				return err
			}
		}
		encoded, err := json.Marshal(children)
		if err != nil {
			return err
		}
		object["data"] = encoded
	}
	return nil
}
