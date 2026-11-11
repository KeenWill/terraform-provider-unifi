package base

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOfficialSelectionDoesNotRejectLegacyHTTPConfiguration(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`{}`))
		case "/proxy/network/api/s/default/stat/sysinfo":
			_, _ = w.Write([]byte(`{"data":[{"version":"11.0.97"}]}`))
		default:
			t.Errorf("unexpected discovery %s", request.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()
	client, err := NewClient(&ClientConfig{URL: server.URL, APIKey: "fixture-key", Site: "default"})
	if err != nil {
		t.Fatal(err)
	}
	before := requests
	if _, err := client.IntegrationClient(); err == nil {
		t.Fatal("official API accepted HTTP origin")
	}
	if requests != before {
		t.Fatal("official selection made a network call")
	}
}
