package device

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"github.com/filipowm/go-unifi/unifi"
	ctyjson "github.com/hashicorp/go-cty/cty/json"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/stretchr/testify/require"

	"github.com/filipowm/terraform-provider-unifi/internal/client/legacy"
	"github.com/filipowm/terraform-provider-unifi/internal/provider/base"
)

// Embedding is confined to this fake: any unexpected SDK operation fails the test.
type fixtureDeviceClient struct {
	unifi.Client
	server *httptest.Server
	device unifi.Device
}

func (c *fixtureDeviceClient) Get(ctx context.Context, path string, request, response interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.server.URL+"/"+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.server.Client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fixture GET: %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(response)
}

func (c *fixtureDeviceClient) Put(ctx context.Context, path string, request, response interface{}) error {
	// Use a real JSON/HTTP boundary, including the production adapter's request type.
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.server.URL+"/"+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	resp, err := c.server.Client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fixture PUT: %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(response)
}

func (c *fixtureDeviceClient) GetDevice(context.Context, string, string) (*unifi.Device, error) {
	return &c.device, nil
}

func (c *fixtureDeviceClient) GetDeviceByMAC(context.Context, string, string) (*unifi.Device, error) {
	return &c.device, nil
}

func fixtureDevice(t *testing.T, filename string) map[string]interface{} {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + filename)
	require.NoError(t, err)
	var response struct {
		Data []map[string]interface{} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(raw, &response))
	return response.Data[0]
}

func fixtureTransport(t *testing.T, device map[string]interface{}, emptyResponse bool) (*base.Client, *[]map[string]interface{}) {
	t.Helper()
	writes := []map[string]interface{}{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/s/default/stat/device":
			require.NoError(t, json.NewEncoder(w).Encode(map[string]interface{}{"meta": map[string]string{"rc": "ok"}, "data": []interface{}{device}}))
		case r.Method == http.MethodPut && r.URL.Path == "/s/default/rest/device/"+fmt.Sprint(device["_id"]):
			var payload map[string]interface{}
			require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
			writes = append(writes, payload)
			if emptyResponse {
				_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[]}`))
				return
			}
			require.NoError(t, json.NewEncoder(w).Encode(map[string]interface{}{"meta": map[string]string{"rc": "ok"}, "data": []interface{}{device}}))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)
	raw, err := json.Marshal(device)
	require.NoError(t, err)
	var typed unifi.Device
	require.NoError(t, json.Unmarshal(raw, &typed))
	return &base.Client{Client: &fixtureDeviceClient{server: server, device: typed}, Site: "default"}, &writes
}

func applyDeviceDiff(t *testing.T, client *base.Client, before, after map[string]interface{}) {
	t.Helper()
	resource := ResourceDevice()
	state := schema.TestResourceDataRaw(t, resource.Schema, before)
	fixture, ok := client.Client.(*fixtureDeviceClient)
	require.True(t, ok)
	state.SetId(fixture.device.ID)
	prior := deviceStateWithConfig(t, resource, state, after)
	difference, err := resource.Diff(context.Background(), prior, terraform.NewResourceConfigRaw(after), client)
	require.NoError(t, err)
	require.NotNil(t, difference, "expected an update")
	require.False(t, difference.RequiresNew(), "existing device must not be replaced")
	_, diagnostics := resource.Apply(context.Background(), prior, difference, client)
	require.False(t, diagnostics.HasError(), "%v", diagnostics)
}

func TestManagementUpdateOmitsUnchangedPortsOnRecordedDevices(t *testing.T) {
	for _, filename := range []string{"recorded-ap.json", "recorded-switch.json", "network11-ap.json", "network11-switch.json"} {
		for _, emptyResponse := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/empty=%t", filename, emptyResponse), func(t *testing.T) {
				device := fixtureDevice(t, filename)
				client, writes := fixtureTransport(t, device, emptyResponse)
				before := map[string]interface{}{"mac": device["mac"], "site": "default", "name": "old", "mgmt_network_id": "old-network", "allow_adoption": false, "forget_on_destroy": false}
				after := map[string]interface{}{
					"mac": device["mac"], "site": "default", "name": "new", "mgmt_network_id": "new-network", "allow_adoption": false, "forget_on_destroy": false,
					"config_network": []interface{}{map[string]interface{}{"type": "static", "ip": "192.0.2.10", "netmask": "255.255.255.0", "gateway": "192.0.2.1", "dns1": "192.0.2.2", "dns2": "192.0.2.3", "dnssuffix": "example.test"}},
				}
				applyDeviceDiff(t, client, before, after)
				require.Len(t, *writes, 1)
				payload := (*writes)[0]
				require.NotContains(t, payload, "port_overrides")
				require.NotContains(t, payload, "radio_table")
				require.NotContains(t, payload, "ether_lighting")
				require.NotContains(t, payload, "adopted")
				require.NotContains(t, payload, "state")
				require.Equal(t, "new-network", payload["mgmt_network_id"])
				require.Equal(t, after["config_network"].([]interface{})[0], payload["config_network"])
			})
		}
	}
}

func TestExistingPortEditPreservesUnmodeledFieldsAndClearIsExplicit(t *testing.T) {
	for _, clear := range []bool{false, true} {
		t.Run(fmt.Sprintf("clear=%t", clear), func(t *testing.T) {
			device := fixtureDevice(t, "recorded-switch.json")
			// Synthetic overlay: preserve fields neither the resource nor pinned SDK knows.
			device["port_overrides"] = []interface{}{map[string]interface{}{"port_idx": 3, "name": "old", "poe_mode": "off", "autoneg": false, "future_setting": map[string]interface{}{"enabled": true}}}
			client, writes := fixtureTransport(t, device, false)
			before := map[string]interface{}{"mac": device["mac"], "site": "default", "name": "fixture-device", "port_override": []interface{}{map[string]interface{}{"number": 3, "name": "old", "poe_mode": "off"}}}
			ports := []interface{}{map[string]interface{}{"number": 3, "name": "new", "poe_mode": "auto"}}
			if clear {
				ports = []interface{}{}
			}
			after := map[string]interface{}{"mac": device["mac"], "site": "default", "name": "fixture-device", "port_override": ports}
			applyDeviceDiff(t, client, before, after)
			require.Len(t, *writes, 1)
			actual, ok := (*writes)[0]["port_overrides"].([]interface{})
			require.True(t, ok, "clear must be [] and omission must be absent")
			if clear {
				require.Empty(t, actual)
				return
			}
			require.Len(t, actual, 1)
			port := actual[0].(map[string]interface{})
			require.Equal(t, "new", port["name"])
			require.Equal(t, "auto", port["poe_mode"])
			require.Equal(t, false, port["autoneg"])
			require.Equal(t, map[string]interface{}{"enabled": true}, port["future_setting"])
		})
	}
}

func TestMalformedRecordedPortStopsBeforeWrite(t *testing.T) {
	client, writes := fixtureTransport(t, fixtureDevice(t, "recorded-switch.json"), false)
	_, err := legacy.UpdateDevice(context.Background(), client, "default", &unifi.Device{ID: "000000000000000000000001", PortOverrides: []unifi.DevicePortOverrides{{PortIDX: 3, Name: "new"}}}, legacy.DeviceChanges{Ports: true})
	require.Error(t, err)
	require.Empty(t, *writes)
}

func TestDeviceLockSerializesMutations(t *testing.T) {
	client := &base.Client{}
	var group sync.WaitGroup
	counter := 0
	for range 20 {
		group.Add(1)
		go func() {
			defer group.Done()
			unlock := client.LockDevice("default", "device")
			defer unlock()
			counter++
		}()
	}
	group.Wait()
	require.Equal(t, 20, counter)
}

func TestUnchangedManagedPortsWithControllerDefaultsHaveNoDiff(t *testing.T) {
	resource := ResourceDevice()
	config := map[string]interface{}{
		"mac": "02:00:00:00:00:01", "site": "default", "name": "fixture-device",
		"port_override": []interface{}{map[string]interface{}{"number": 3, "name": "port", "poe_mode": "auto"}},
	}
	state := schema.TestResourceDataRaw(t, resource.Schema, config)
	state.SetId("000000000000000000000001")
	current := &unifi.Device{
		ID: state.Id(), MAC: config["mac"].(string), Name: "fixture-device",
		PortOverrides: []unifi.DevicePortOverrides{{PortIDX: 3, Name: "port", PoeMode: "auto", OpMode: "switch", SettingPreference: "manual", NATiveNetworkID: "controller-network", Forward: "all"}},
	}
	require.False(t, resourceDeviceSetResourceData(current, state, "default").HasError())
	difference, err := resource.Diff(context.Background(), deviceStateWithConfig(t, resource, state, config), terraform.NewResourceConfigRaw(config), nil)
	require.NoError(t, err)
	require.True(t, difference.Empty(), "unchanged configuration should not write ports: %#v", difference)
	config["name"] = "renamed"
	difference, err = resource.Diff(context.Background(), deviceStateWithConfig(t, resource, state, config), terraform.NewResourceConfigRaw(config), nil)
	require.NoError(t, err)
	for field := range difference.Attributes {
		require.NotContains(t, field, "port_override", "name-only updates must omit unchanged ports")
	}
}

func TestRadioAndEtherlightingRemainInPartialDevicePayload(t *testing.T) {
	device := fixtureDevice(t, "recorded-ap.json")
	device["radio_table"] = []interface{}{
		map[string]interface{}{"radio": "ng", "channel": "6", "ht": 20},
		map[string]interface{}{"radio": "na", "channel": "36", "ht": 80},
	}
	device["ether_lighting"] = map[string]interface{}{"mode": "speed", "brightness": 80}
	client, writes := fixtureTransport(t, device, false)
	before := map[string]interface{}{"mac": device["mac"], "site": "default", "name": "old"}
	after := map[string]interface{}{
		"mac": device["mac"], "site": "default", "name": "new", "switch_vlan_enabled": true,
		"radio":          []interface{}{map[string]interface{}{"name": "ng", "channel": "11"}},
		"ether_lighting": []interface{}{map[string]interface{}{"mode": "network"}},
	}
	applyDeviceDiff(t, client, before, after)
	require.Len(t, *writes, 1)
	payload := (*writes)[0]
	require.NotContains(t, payload, "port_overrides")
	require.Equal(t, true, payload["switch_vlan_enabled"])
	radios := payload["radio_table"].([]interface{})
	require.Len(t, radios, 2)
	require.Equal(t, "11", radios[0].(map[string]interface{})["channel"])
	require.Equal(t, "36", radios[1].(map[string]interface{})["channel"])
	lighting := payload["ether_lighting"].(map[string]interface{})
	require.Equal(t, "network", lighting["mode"])
	require.Equal(t, float64(80), lighting["brightness"])
}

func deviceStateWithConfig(t *testing.T, resource *schema.Resource, state *schema.ResourceData, config map[string]interface{}) *terraform.InstanceState {
	t.Helper()
	raw, err := json.Marshal(config)
	require.NoError(t, err)
	var value ctyjson.SimpleJSONValue
	require.NoError(t, value.UnmarshalJSON(raw))
	coerced, err := resource.CoreConfigSchema().CoerceValue(value.Value)
	require.NoError(t, err)
	result := state.State()
	if result == nil {
		result = &terraform.InstanceState{Attributes: map[string]string{}}
	}
	result.RawConfig = coerced
	return result
}

func TestDeviceExplicitFalseAndManagementEmptyValuesReachWire(t *testing.T) {
	device := fixtureDevice(t, "recorded-ap.json")
	client, writes := fixtureTransport(t, device, false)
	before := map[string]interface{}{"mac": device["mac"], "site": "default", "name": "fixture", "switch_vlan_enabled": true}
	after := map[string]interface{}{
		"mac": device["mac"], "site": "default", "name": "fixture", "switch_vlan_enabled": false,
		"config_network": []interface{}{map[string]interface{}{"type": "dhcp", "ip": "", "netmask": "", "gateway": "", "dns1": "", "dns2": "", "dnssuffix": ""}},
	}
	applyDeviceDiff(t, client, before, after)
	require.Len(t, *writes, 1)
	require.Equal(t, false, (*writes)[0]["switch_vlan_enabled"])
	require.Equal(t, after["config_network"].([]interface{})[0], (*writes)[0]["config_network"])
	require.NotContains(t, (*writes)[0], "port_overrides")
}

func TestDeviceImportRetainsIdentityAndManagementStateWithoutWrites(t *testing.T) {
	device := fixtureDevice(t, "recorded-ap.json")
	device["mgmt_network_id"] = "management-network"
	client, writes := fixtureTransport(t, device, false)
	resource := ResourceDevice()
	state := schema.TestResourceDataRaw(t, resource.Schema, map[string]interface{}{"allow_adoption": false, "forget_on_destroy": false})
	state.SetId("default:" + device["mac"].(string))
	imported, err := resource.Importer.StateContext(context.Background(), state, client)
	require.NoError(t, err)
	require.Len(t, imported, 1)
	require.Equal(t, device["_id"], imported[0].Id())
	require.False(t, resource.ReadContext(context.Background(), state, client).HasError())
	require.Equal(t, "management-network", state.Get("mgmt_network_id"))
	require.Equal(t, "dhcp", state.Get("config_network.0.type"))
	require.Equal(t, "192.0.2.10", state.Get("config_network.0.ip"))
	require.Equal(t, false, state.Get("forget_on_destroy"))
	require.Empty(t, *writes)
}

func TestInitialManagementPreservesOmittedExclusionsAndHonorsExplicitClear(t *testing.T) {
	for _, clear := range []bool{false, true} {
		t.Run(fmt.Sprintf("explicit-clear=%t", clear), func(t *testing.T) {
			device := fixtureDevice(t, "recorded-switch.json")
			device["adopted"] = true
			device["port_overrides"] = []interface{}{map[string]interface{}{
				"port_idx": 3, "forward": "customize", "excluded_networkconf_ids": []interface{}{"restricted-vlan"},
			}}
			client, writes := fixtureTransport(t, device, false)
			port := map[string]interface{}{"number": 3, "name": "managed-port"}
			if clear {
				port["excluded_network_ids"] = []interface{}{}
			}
			config := map[string]interface{}{
				"mac": device["mac"], "site": "default", "allow_adoption": false, "forget_on_destroy": false,
				"port_override": []interface{}{port},
			}
			resource := ResourceDevice()
			state := schema.TestResourceDataRaw(t, resource.Schema, map[string]interface{}{})
			prior := deviceStateWithConfig(t, resource, state, config)
			difference, err := resource.Diff(context.Background(), prior, terraform.NewResourceConfigRaw(config), client)
			require.NoError(t, err)
			// Preserve protocol configuration in this SDK-level create simulation.
			difference.RawConfig = prior.RawConfig
			_, diagnostics := resource.Apply(context.Background(), prior, difference, client)
			require.False(t, diagnostics.HasError(), "%v", diagnostics)
			require.Len(t, *writes, 1)
			payload := (*writes)[0]["port_overrides"].([]interface{})[0].(map[string]interface{})
			require.Equal(t, "customize", payload["forward"])
			if clear {
				require.Equal(t, []interface{}{}, payload["excluded_networkconf_ids"])
			} else {
				require.Equal(t, []interface{}{"restricted-vlan"}, payload["excluded_networkconf_ids"])
			}
		})
	}
}
