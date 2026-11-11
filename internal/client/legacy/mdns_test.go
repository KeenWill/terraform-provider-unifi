package legacy

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type mdnsTransport struct {
	version     string
	document    map[string]interface{}
	writes      []map[string]interface{}
	ignoreWrite bool
}

func (m *mdnsTransport) Get(_ context.Context, path string, _ interface{}, response interface{}) error {
	var value interface{} = m.document
	if strings.HasSuffix(path, "/stat/sysinfo") {
		value = map[string]interface{}{"data": []map[string]string{{"version": m.version}}}
	}
	b, _ := json.Marshal(value)
	return json.Unmarshal(b, response)
}
func (m *mdnsTransport) Put(_ context.Context, _ string, body interface{}, response interface{}) error {
	payload := body.(map[string]interface{})
	m.writes = append(m.writes, payload)
	if !m.ignoreWrite {
		for k, v := range payload {
			m.document[k] = v
		}
		if payload["mdns_enabled_for"] == "none" {
			m.document["mdns_enabled_for_network_ids"] = []string{}
		}
	}
	b, _ := json.Marshal(m.document)
	return json.Unmarshal(b, response)
}
func mdnsFixture() *mdnsTransport {
	return &mdnsTransport{version: "11.0.99", document: map[string]interface{}{
		"mdns_enabled_for": "all", "mdns_enabled_for_network_ids": []string{"existing"}, "default_security_posture": "BLOCK_ALL", "future_setting": map[string]interface{}{"enabled": true},
	}}
}
func TestMDNSScopeNarrowWriteAndVerification(t *testing.T) {
	c := mdnsFixture()
	value, err := UpdateMDNSScope(context.Background(), c, "default", MDNSScope{Scope: "none"})
	require.NoError(t, err)
	require.Equal(t, "none", value.Scope)
	require.Equal(t, map[string]interface{}{"mdns_enabled_for": "none"}, c.writes[0])
	require.Equal(t, "BLOCK_ALL", c.document["default_security_posture"])
	value, err = UpdateMDNSScope(context.Background(), c, "default", MDNSScope{ID: "mdns-scope", Scope: "some", NetworkIDs: []string{"declared"}})
	require.NoError(t, err)
	require.Equal(t, []string{"declared"}, value.NetworkIDs)
	require.Len(t, c.writes[1], 2)
}
func TestMDNSScopeUnknownVersionAndShapeRefuseWrites(t *testing.T) {
	for _, version := range []string{"", "11.0.100", "10.6.106", "12.0.1"} {
		c := mdnsFixture()
		c.version = version
		_, err := UpdateMDNSScope(context.Background(), c, "default", MDNSScope{Scope: "none"})
		require.Error(t, err)
		require.Empty(t, c.writes)
	}
	c := mdnsFixture()
	delete(c.document, "mdns_enabled_for_network_ids")
	_, err := UpdateMDNSScope(context.Background(), c, "default", MDNSScope{Scope: "none"})
	require.Error(t, err)
	require.Empty(t, c.writes)
}
func TestMDNSScopeDoesNotTrustSuccessfulWriteEcho(t *testing.T) {
	c := mdnsFixture()
	c.ignoreWrite = true
	_, err := UpdateMDNSScope(context.Background(), c, "default", MDNSScope{Scope: "none"})
	require.ErrorContains(t, err, "readback")
}
