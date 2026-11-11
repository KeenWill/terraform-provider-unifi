package integration

import (
	"context"
	"encoding/json"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFlowPatchGuards(t *testing.T) {
	for _, tc := range []struct {
		name, version, origin string
		missing, mismatch     bool
		writes                int
		fail                  bool
	}{
		{name: "one field", version: "11.0.99", origin: "USER_DEFINED", writes: 1},
		{name: "unknown version", version: "11.0.100", origin: "USER_DEFINED", fail: true},
		{name: "predefined", version: "11.0.99", origin: "SYSTEM_DEFINED", fail: true},
		{name: "missing field", version: "11.0.99", origin: "USER_DEFINED", missing: true, fail: true},
		{name: "ignored write", version: "11.0.99", origin: "USER_DEFINED", mismatch: true, writes: 1, fail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enabled := false
			writes := 0
			gets := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "lab-key", r.Header.Get("X-API-KEY"))
				if r.URL.Path == "/proxy/network/integration/v1/info" {
					json.NewEncoder(w).Encode(map[string]string{"applicationVersion": tc.version})
					return
				}
				require.Equal(t, "/proxy/network/integration/v1/sites/site/firewall/policies/policy", r.URL.Path)
				if r.Method == "PATCH" {
					require.Greater(t, gets, 0)
					writes++
					var body map[string]any
					require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
					require.Equal(t, map[string]any{"reportFlowEnabled": true}, body)
					if !tc.mismatch {
						enabled = true
					}
				}
				if r.Method == "GET" {
					gets++
				}
				document := map[string]any{"id": "policy", "metadata": map[string]any{"origin": tc.origin}, "unknownFutureField": "preserved"}
				if !tc.missing {
					document["reportFlowEnabled"] = enabled
				}
				json.NewEncoder(w).Encode(document)
			}))
			defer server.Close()
			c, err := New(server.URL, "lab-key", server.Client().Transport)
			require.NoError(t, err)
			p, err := c.SetFlowReporting(context.Background(), "site", "policy", true)
			if tc.fail {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.True(t, p.Enabled)
				require.Equal(t, "preserved", p.Document["unknownFutureField"])
			}
			require.Equal(t, tc.writes, writes)
		})
	}
}
