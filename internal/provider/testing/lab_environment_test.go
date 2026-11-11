package testing

import "testing"

func TestLabEndpointRejectsNonDisposableOrigins(t *testing.T) {
	for _, endpoint := range []string{"https://10.0.1.1", "https://localhost:25443", "http://127.0.0.1:25443",
		"https://127.0.0.1:443", "https://127.0.0.1:25443/path", "https://user@127.0.0.1:25443",
		"https://127.0.0.1:25443?forward=controller", "https://127.0.0.1:25443#fragment", "https://[::1]:25443"} {
		if validateLabEndpoint(endpoint) == nil {
			t.Errorf("accepted non-lab endpoint %q", endpoint)
		}
	}
	if err := validateLabEndpoint("https://127.0.0.1:25443"); err != nil {
		t.Fatal(err)
	}
}
