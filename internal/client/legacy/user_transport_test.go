package legacy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/filipowm/go-unifi/unifi"
)

func TestFingerprintVariants(t *testing.T) {
	for _, value := range []string{`1908`, `"1908"`, `null`, `""`, `0`} {
		payload := []byte(`{"meta":{"rc":"ok"},"data":[{"_id":"000123","dev_id_override":` + value + `} ]}`)
		normalized, err := normalizeUserResponse(payload)
		if err != nil {
			t.Fatal(err)
		}
		var response struct {
			Data []unifi.User `json:"data"`
		}
		if err := json.Unmarshal(normalized, &response); err != nil {
			t.Fatal(err)
		}
		if response.Data[0].ID != "000123" {
			t.Fatal("converted opaque ID")
		}
		expected := 0
		if strings.Contains(value, "1908") {
			expected = 1908
		}
		if response.Data[0].DevIdOverride != expected {
			t.Fatal("wrong fingerprint")
		}
	}
	for _, value := range []string{`"secret"`, `"1.5"`, `"-1"`, `"9999999999999999999999999999999"`} {
		_, err := normalizeUserResponse([]byte(`{"data":[{"dev_id_override":` + value + `}]}`))
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("error %v", err)
		}
	}
}

func TestUserTransportReplaysNetwork11AndNestedCreate(t *testing.T) {
	payload, err := os.ReadFile("testdata/network11/configured-users.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/proxy/network/api/s/default/rest/user", "/proxy/network/api/s/default/stat/user/02:00:00:00:00:11", "/proxy/network/api/s/default/group/user", "/proxy/network/api/s/default/cmd/stamgr"} {
		t.Run(path, func(t *testing.T) {
			responsePayload := payload
			if strings.HasSuffix(path, "group/user") {
				responsePayload = []byte(`{"meta":{"rc":"ok"},"data":[` + string(payload) + `]}`)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(responsePayload) }))
			defer server.Close()
			client := &http.Client{Transport: &UserCompatibilityTransport{Next: server.Client().Transport}}
			request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if strings.HasSuffix(path, "group/user") {
				var envelope struct {
					Data []struct {
						Data []unifi.User `json:"data"`
					} `json:"data"`
				}
				if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
					t.Fatal(err)
				}
				if envelope.Data[0].Data[0].DevIdOverride != 1908 {
					t.Fatal("nested decode failed")
				}
			} else {
				var envelope struct {
					Data []unifi.User `json:"data"`
				}
				if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
					t.Fatal(err)
				}
				if envelope.Data[0].DevIdOverride != 1908 {
					t.Fatal("decode failed")
				}
			}
		})
	}
}

type usersFixture struct {
	users []unifi.User
	err   error
	site  string
}

func (f *usersFixture) ListUser(_ context.Context, site string) ([]unifi.User, error) {
	f.site = site
	return f.users, f.err
}

func TestConfiguredIdentityIsScopedAndUnambiguous(t *testing.T) {
	fixture := &usersFixture{users: []unifi.User{{ID: "configured", MAC: "02:00:00:00:00:aa", Name: "same"}, {ID: "other", MAC: "02:00:00:00:00:bb", Name: "same"}}}
	user, err := ConfiguredUserByMAC(context.Background(), fixture, "site-a", "02:00:00:00:00:AA")
	if err != nil || user.ID != "configured" || fixture.site != "site-a" {
		t.Fatalf("%v %v", user, err)
	}
	fixture.users = append(fixture.users, fixture.users[0])
	if _, err := ConfiguredUserByMAC(context.Background(), fixture, "site-a", "02:00:00:00:00:aa"); err == nil {
		t.Fatal("accepted duplicate")
	}
	fixture.err = errors.New("unauthorized")
	if _, err := ConfiguredUserByMAC(context.Background(), fixture, "site-a", "02:00:00:00:00:aa"); !errors.Is(err, fixture.err) {
		t.Fatal("lost auth error")
	}
}
