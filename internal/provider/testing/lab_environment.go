package testing

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"testing"

	"github.com/filipowm/terraform-provider-unifi/internal/provider/base"
)

// labManifest is created privately by tools/firmware/lab.py for its own QEMU
// loopback forward. It is never a production controller configuration.
type labManifest struct {
	Endpoint string `json:"endpoint"`
	Username string `json:"username"`
	Password string `json:"password"`
	Version  string `json:"version"`
}

func validateLabEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return errors.New("invalid disposable lab endpoint")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1024 || port > 65535 || u.Scheme != "https" ||
		u.Hostname() != "127.0.0.1" || u.User != nil || u.Path != "" ||
		u.RawQuery != "" || u.Fragment != "" {
		return errors.New("disposable lab endpoint must be an HTTPS IPv4 loopback origin on an explicit unprivileged port")
	}
	return nil
}

func runLab(m *testing.M, callback func(env *TestEnvironment), filename string) int {
	fail := func(message string) int { fmt.Fprintln(os.Stderr, message); return 1 }
	info, err := os.Stat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return fail("acceptance lab manifest must be an owner-only regular file")
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return fail("cannot read acceptance lab manifest")
	}
	var manifest labManifest
	if json.Unmarshal(data, &manifest) != nil || manifest.Username == "" || manifest.Password == "" || manifest.Version == "" {
		return fail("incomplete acceptance lab manifest")
	}
	if err := validateLabEndpoint(manifest.Endpoint); err != nil {
		return fail(err.Error())
	}
	client, err := base.NewClient(&base.ClientConfig{URL: manifest.Endpoint,
		Username: manifest.Username, Password: manifest.Password, Insecure: true, Site: "default"})
	if err != nil {
		return fail("cannot authenticate disposable acceptance controller")
	}
	if client.Version.String() != manifest.Version {
		return fail("disposable acceptance controller version differs from the lab manifest")
	}
	for name, value := range map[string]string{"UNIFI_API": manifest.Endpoint,
		"UNIFI_USERNAME": manifest.Username, "UNIFI_PASSWORD": manifest.Password,
		"UNIFI_INSECURE": "true", "UNIFI_SITE": "default", "UNIFI_API_KEY": ""} {
		if os.Setenv(name, value) != nil {
			return fail("cannot configure disposable acceptance environment")
		}
	}
	callback(&TestEnvironment{Client: client.Client, Endpoint: manifest.Endpoint, Shutdown: func() {}})
	return m.Run()
}
