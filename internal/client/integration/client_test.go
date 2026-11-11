package integration

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func fixtureClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	client, err := New(server.URL, "fixture-key", server.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestNetwork11Inventory(t *testing.T) {
	const site = SiteID("00000000-0000-4000-8000-000000000001")
	const deviceID = ObjectID("00000000-0000-4000-8000-000000000002")
	routes := map[string]string{"/info": "info", "/sites": "sites", "/sites/" + string(site) + "/devices/" + string(deviceID): "device", "/sites/" + string(site) + "/firewall/policies": "policies"}
	client := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("X-API-KEY") != "fixture-key" || r.Header.Get("Cookie") != "" {
			t.Error("unexpected method or authentication")
		}
		name, found := routes[strings.TrimPrefix(r.URL.Path, "/proxy/network/integration/v1")]
		if !found {
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		data, err := os.ReadFile("testdata/network11/" + name + ".json")
		if err != nil {
			t.Error(err)
		}
		_, _ = w.Write(data)
	})
	ctx := context.Background()
	info, err := client.Info(ctx)
	if err != nil || info.ApplicationVersion != "11.0.97" {
		t.Fatalf("info: %v %v", info, err)
	}
	sites, err := client.Sites(ctx)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := ResolveSite(sites, "default")
	if err != nil || resolved != site {
		t.Fatalf("site: %v %v", resolved, err)
	}
	device, err := client.Device(ctx, site, deviceID)
	if err != nil {
		t.Fatal(err)
	}
	radio := device.Interfaces.Radios[0]
	if radio.WLANStandard != "802.11ah" || radio.TXPowerMode == nil || *radio.TXPowerMode != "AUTO" || radio.Channel != nil {
		t.Fatalf("radio: %+v", radio)
	}
	policies, err := client.Policies(ctx, site)
	if err != nil {
		t.Fatal(err)
	}
	if policies[0].ReportFlowEnabled == nil || *policies[0].ReportFlowEnabled || policies[0].Description != nil || policies[0].ConnectionStateFilter != nil {
		t.Fatalf("policy: %+v", policies[0])
	}
}

func TestErrorsAreDistinctAndRedacted(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusFound} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			calls := 0
			client := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("Location", "https://secret.invalid")
				w.WriteHeader(status)
				_, _ = w.Write([]byte("secret body fixture-key"))
			})
			_, err := client.Info(context.Background())
			var httpError *HTTPError
			if !errors.As(err, &httpError) || httpError.StatusCode != status || strings.Contains(err.Error(), "secret") {
				t.Fatalf("error: %v", err)
			}
			expected := 1
			if status == http.StatusTooManyRequests || status == http.StatusInternalServerError {
				expected = readAttempts
			}
			if calls != expected {
				t.Fatalf("calls %d expected %d", calls, expected)
			}
		})
	}
}

func TestPaginationAndAmbiguousSites(t *testing.T) {
	calls := 0
	client := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("offset") != strconv.Itoa(calls) || r.URL.Query().Get("limit") != "200" {
			t.Error("incorrect page query")
		}
		_, _ = fmt.Fprintf(w, `{"offset":%d,"limit":1,"count":1,"totalCount":2,"data":[{"id":"site-%d","internalReference":"default","name":"Duplicate"}]}`, calls, calls)
		calls++
	})
	sites, err := client.Sites(context.Background())
	if err != nil || len(sites) != 2 {
		t.Fatalf("sites %v error %v", sites, err)
	}
	if _, err := ResolveSite(sites, "default"); err == nil {
		t.Fatal("accepted ambiguous site")
	}
	if _, err := ResolveSite(sites, "Duplicate"); err == nil {
		t.Fatal("accepted display name")
	}
}

func TestMalformedResponsesFailClosed(t *testing.T) {
	for _, body := range []string{`null`, `{}`, `<html>secret</html>`, `{"offset":0,"limit":1,"count":0,"totalCount":2,"data":[]}`, `{"offset":0,"limit":1,"count":2,"totalCount":2,"data":[]}`, `{"offset":0,"limit":1,"count":0,"totalCount":0,"data":null}`, strings.Repeat(" ", maxResponseBytes+1)} {
		client := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) })
		if _, err := client.Sites(context.Background()); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("error: %v", err)
		}
	}
}

func TestTLSValidationAndCancellation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTooManyRequests) }))
	defer server.Close()
	client, err := New(server.URL, "fixture-key", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Info(context.Background()); err == nil {
		t.Fatal("accepted untrusted certificate")
	}
	client, err = New(server.URL, "fixture-key", server.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := client.Info(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error %v", err)
	}
}

func TestUnsafeOriginsAndIdentifiers(t *testing.T) {
	for _, origin := range []string{"http://localhost", "https://user:secret@localhost", "https://localhost/path", "https://localhost?secret=x", "https://localhost#secret"} {
		if _, err := New(origin, "fixture-key", nil); err == nil {
			t.Fatalf("accepted %s", origin)
		}
	}
	client := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) { t.Error("unexpected request") })
	for _, id := range []string{"", "..", "a/b", "%2f", "a?b", "a\\b"} {
		if _, err := client.Device(context.Background(), SiteID(id), "device"); err == nil {
			t.Fatalf("accepted %s", id)
		}
	}
}

func TestOlderAPIFieldsStayAbsent(t *testing.T) {
	client := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/devices/device") {
			_, _ = w.Write([]byte(`{"id":"device","macAddress":"02:00:00:00:00:02","interfaces":{"radios":[{"frequencyGHz":5,"channelWidthMHz":40,"wlanStandard":"802.11ax"}]}}`))
			return
		}
		_, _ = w.Write([]byte(`{"offset":0,"limit":200,"count":1,"totalCount":1,"data":[{"id":"policy","name":"Policy","description":"","connectionStateFilter":["ESTABLISHED"]}]}`))
	})
	device, err := client.Device(context.Background(), "site", "device")
	if err != nil {
		t.Fatal(err)
	}
	if device.Interfaces.Radios[0].TXPowerMode != nil {
		t.Fatal("invented transmit power mode")
	}
	policies, err := client.Policies(context.Background(), "site")
	if err != nil {
		t.Fatal(err)
	}
	if policies[0].ReportFlowEnabled != nil || policies[0].Description == nil || *policies[0].Description != "" || len(policies[0].ConnectionStateFilter) != 1 {
		t.Fatal("lost absent/empty distinction")
	}
}
