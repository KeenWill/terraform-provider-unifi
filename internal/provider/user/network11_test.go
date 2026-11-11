package user

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/filipowm/terraform-provider-unifi/internal/provider/base"
)

const (
	reservationID  = "00000000-0000-4000-8000-000000000011"
	reservationMAC = "02:00:00:00:00:11"
)

func network11Client(t *testing.T, configStatus, statStatus int, configFixture, statFixture string) *base.Client {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected mutation %s", r.Method)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if r.URL.Path == "/" {
			_, _ = w.Write([]byte(`{}`))
			return
		}
		if r.Header.Get("X-API-KEY") != "fixture-key" {
			t.Error("missing fixture API key")
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/proxy/network/api/s/default/stat/sysinfo" {
			_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[{"version":"11.0.97"}]}`))
			return
		}
		fixture := ""
		var status int
		switch r.URL.Path {
		case "/proxy/network/api/s/default/rest/user", "/proxy/network/api/s/default/rest/user/" + reservationID:
			fixture = configFixture
			status = configStatus
		case "/proxy/network/api/s/default/stat/user/" + reservationMAC:
			fixture = statFixture
			status = statStatus
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(status)
		if status != http.StatusOK {
			_, _ = w.Write([]byte(`{"meta":{"rc":"error","msg":"api.err.NoPermission"},"data":[]}`))
			return
		}
		data, err := os.ReadFile("../../client/legacy/testdata/network11/" + fixture)
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = w.Write(data)
	}))
	t.Cleanup(server.Close)
	client, err := base.NewClient(&base.ClientConfig{URL: server.URL, APIKey: "fixture-key", Site: "default", HTTPConfigurer: func() http.RoundTripper { return server.Client().Transport }})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestReservationRefreshWithoutStatisticsKeepsConfiguration(t *testing.T) {
	for _, stats := range []string{"observed-user.json", "empty-statistics.json"} {
		t.Run(stats, func(t *testing.T) {
			client := network11Client(t, 200, 200, "configured-users.json", stats)
			data := schema.TestResourceDataRaw(t, ResourceUser().Schema, map[string]interface{}{"mac": reservationMAC, "name": "Fixture reservation"})
			data.SetId(reservationID)
			diagnostics := resourceUserRead(context.Background(), data, client)
			if diagnostics.HasError() {
				t.Fatal(diagnostics)
			}
			if data.Id() != reservationID || data.Get("fixed_ip") != "192.0.2.11" || data.Get("dev_id_override") != 1908 {
				t.Fatalf("lost reservation: %v", data.State())
			}
			expectedIP := "192.0.2.11"
			if stats == "empty-statistics.json" {
				expectedIP = ""
			}
			if data.Get("ip") != expectedIP {
				t.Fatal("incorrect observed IP")
			}
		})
	}
}

func TestDataUserUsesConfiguredIDNotObservedID(t *testing.T) {
	for _, stats := range []string{"observed-user.json", "empty-statistics.json"} {
		t.Run(stats, func(t *testing.T) {
			client := network11Client(t, 200, 200, "configured-users.json", stats)
			data := schema.TestResourceDataRaw(t, DataUser().Schema, map[string]interface{}{"mac": reservationMAC})
			if diagnostics := dataUserRead(context.Background(), data, client); diagnostics.HasError() {
				t.Fatal(diagnostics)
			}
			if data.Id() != reservationID || data.Get("fixed_ip") != "192.0.2.11" {
				t.Fatal("used observation identity")
			}
		})
	}
}

func TestRefreshErrorsRetainManagedIdentity(t *testing.T) {
	for _, test := range []struct {
		name                     string
		configStatus, statStatus int
		fixture                  string
	}{
		{"missing-config", 200, 200, "empty-statistics.json"},
		{"config-unauthorized", 401, 200, "configured-users.json"},
		{"stats-forbidden", 200, 403, "configured-users.json"},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := network11Client(t, test.configStatus, test.statStatus, test.fixture, "empty-statistics.json")
			data := schema.TestResourceDataRaw(t, ResourceUser().Schema, map[string]interface{}{"mac": reservationMAC, "name": "previous", "fixed_ip": "192.0.2.11"})
			data.SetId(reservationID)
			diagnostics := resourceUserRead(context.Background(), data, client)
			if !diagnostics.HasError() || data.Id() != reservationID || data.Get("name") != "previous" {
				t.Fatalf("lost state: %v %v", diagnostics, data.State())
			}
			if test.name == "missing-config" && !strings.Contains(fmt.Sprint(diagnostics), "reconciliation required") {
				t.Fatal("missing migration diagnostic")
			}
		})
	}
}
