package device

import (
	"reflect"
	"testing"

	"github.com/filipowm/go-unifi/unifi"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func TestDeviceConfigNetworkExpandFlatten(t *testing.T) {
	input := []interface{}{
		map[string]interface{}{
			"type":      "static",
			"ip":        "10.0.10.100",
			"netmask":   "255.255.255.0",
			"gateway":   "10.0.10.1",
			"dns1":      "1.1.1.1",
			"dns2":      "1.0.0.1",
			"dnssuffix": "home.arpa",
		},
	}

	got, err := expandDeviceConfigNetwork(input)
	if err != nil {
		t.Fatalf("expandDeviceConfigNetwork returned error: %v", err)
	}

	want := unifi.DeviceConfigNetwork{
		Type:      "static",
		IP:        "10.0.10.100",
		Netmask:   "255.255.255.0",
		Gateway:   "10.0.10.1",
		DNS1:      "1.1.1.1",
		DNS2:      "1.0.0.1",
		DNSsuffix: "home.arpa",
	}
	if got != want {
		t.Fatalf("expanded config network mismatch\nwant: %#v\n got: %#v", want, got)
	}

	flattened := flattenDeviceConfigNetwork(got)
	if !reflect.DeepEqual(flattened, []map[string]interface{}{input[0].(map[string]interface{})}) {
		t.Fatalf("flattened config network mismatch\nwant: %#v\n got: %#v", input, flattened)
	}
}

func TestDeviceConfigNetworkFlattenZeroValue(t *testing.T) {
	got := flattenDeviceConfigNetwork(unifi.DeviceConfigNetwork{})
	if got != nil {
		t.Fatalf("expected nil flattened config for zero value, got %#v", got)
	}
}

func TestResourceDeviceGetResourceDataIncludesManagementNetwork(t *testing.T) {
	resourceData := schema.TestResourceDataRaw(t, ResourceDevice().Schema, map[string]interface{}{
		"mac":             "01:23:45:67:89:ab",
		"name":            "office-ap",
		"mgmt_network_id": "network-management-id",
		"config_network": []interface{}{
			map[string]interface{}{
				"type":      "static",
				"ip":        "10.0.10.100",
				"netmask":   "255.255.255.0",
				"gateway":   "10.0.10.1",
				"dns1":      "1.1.1.1",
				"dns2":      "1.0.0.1",
				"dnssuffix": "",
			},
		},
	})

	got, err := resourceDeviceGetResourceData(resourceData, false)
	if err != nil {
		t.Fatalf("resourceDeviceGetResourceData returned error: %v", err)
	}

	if got.MgmtNetworkID != "network-management-id" {
		t.Fatalf("expected management network ID to be set, got %q", got.MgmtNetworkID)
	}

	wantConfigNetwork := unifi.DeviceConfigNetwork{
		Type:    "static",
		IP:      "10.0.10.100",
		Netmask: "255.255.255.0",
		Gateway: "10.0.10.1",
		DNS1:    "1.1.1.1",
		DNS2:    "1.0.0.1",
	}
	if got.ConfigNetwork != wantConfigNetwork {
		t.Fatalf("config network mismatch\nwant: %#v\n got: %#v", wantConfigNetwork, got.ConfigNetwork)
	}
}

func TestResourceDeviceGetResourceDataOmitsPortOverridesWhenUnchanged(t *testing.T) {
	resourceData := schema.TestResourceDataRaw(t, ResourceDevice().Schema, map[string]interface{}{
		"mac":  "01:23:45:67:89:ab",
		"name": "office-ap",
		"port_override": []interface{}{
			map[string]interface{}{
				"number": 1,
				"name":   "existing label",
			},
		},
	})

	got, err := resourceDeviceGetResourceData(resourceData, false)
	if err != nil {
		t.Fatalf("resourceDeviceGetResourceData returned error: %v", err)
	}

	if got.PortOverrides != nil {
		t.Fatalf("expected port overrides to be omitted, got %#v", got.PortOverrides)
	}
}
