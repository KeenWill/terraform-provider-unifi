// Package legacy owns adapters for the unsupported Network REST and private v2 APIs.
package legacy

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/filipowm/go-unifi/unifi"
)

// DeviceTransport is the legacy transport boundary; it does not select an API backend.
type DeviceTransport interface {
	Get(context.Context, string, interface{}, interface{}) error
	Put(context.Context, string, interface{}, interface{}) error
}

type deviceUpdate struct {
	MAC               string                        `json:"mac,omitempty"`
	Name              string                        `json:"name,omitempty"`
	MgmtNetworkID     string                        `json:"mgmt_network_id,omitempty"`
	ConfigNetwork     *deviceConfigNetwork          `json:"config_network,omitempty"`
	SwitchVLANEnabled *bool                         `json:"switch_vlan_enabled,omitempty"`
	PortOverrides     *[]map[string]json.RawMessage `json:"port_overrides,omitempty"`
	RadioTable        []unifi.DeviceRadioTable      `json:"radio_table,omitempty"`
	EtherLighting     *unifi.DeviceEtherLighting    `json:"ether_lighting,omitempty"`
}

// DeviceChanges identifies fields whose omission differs from an explicit clear.
type DeviceChanges struct {
	Ports          bool
	SwitchVLAN     bool
	PortExclusions map[int]bool
}

// Empty management values must reach the controller when explicitly cleared.
type deviceConfigNetwork struct {
	Type      string `json:"type"`
	IP        string `json:"ip"`
	Netmask   string `json:"netmask"`
	Gateway   string `json:"gateway"`
	DNS1      string `json:"dns1"`
	DNS2      string `json:"dns2"`
	DNSSuffix string `json:"dnssuffix"`
}

// UpdateDevice sends only supported configuration fields. A nil ports pointer
// omits the field; a pointer to an empty array deliberately clears overrides.
// Callers must serialize the entire read/merge/write sequence for this device.
func UpdateDevice(ctx context.Context, client DeviceTransport, site string, device *unifi.Device, changes DeviceChanges) (*unifi.Device, error) {
	request := deviceUpdate{
		MAC: device.MAC, Name: device.Name, MgmtNetworkID: device.MgmtNetworkID,
		RadioTable: device.RadioTable,
	}
	if device.ConfigNetwork != (unifi.DeviceConfigNetwork{}) {
		config := device.ConfigNetwork
		request.ConfigNetwork = &deviceConfigNetwork{Type: config.Type, IP: config.IP, Netmask: config.Netmask, Gateway: config.Gateway, DNS1: config.DNS1, DNS2: config.DNS2, DNSSuffix: config.DNSsuffix}
	}
	if device.EtherLighting != (unifi.DeviceEtherLighting{}) {
		request.EtherLighting = &device.EtherLighting
	}
	if changes.SwitchVLAN {
		request.SwitchVLANEnabled = &device.SwitchVLANEnabled
	}
	if changes.Ports {
		ports, err := mergeDevicePorts(ctx, client, site, device, changes.PortExclusions)
		if err != nil {
			return nil, err
		}
		request.PortOverrides = &ports
	}
	var response struct {
		Meta unifi.Meta     `json:"meta"`
		Data []unifi.Device `json:"data"`
	}
	if err := client.Put(ctx, fmt.Sprintf("s/%s/rest/device/%s", site, device.ID), request, &response); err != nil {
		return nil, err
	}
	if len(response.Data) == 0 {
		return nil, unifi.ErrNotFound
	}
	if len(response.Data) != 1 {
		return nil, fmt.Errorf("device update returned %d devices", len(response.Data))
	}
	return &response.Data[0], nil
}

func mergeDevicePorts(ctx context.Context, client DeviceTransport, site string, device *unifi.Device, configuredExclusions map[int]bool) ([]map[string]json.RawMessage, error) {
	result := make([]map[string]json.RawMessage, 0, len(device.PortOverrides))
	// Explicit clearing has no values to preserve and must encode as [], never null.
	if len(device.PortOverrides) == 0 {
		return result, nil
	}
	var response struct {
		Data []struct {
			ID    string                       `json:"_id"`
			Ports []map[string]json.RawMessage `json:"port_overrides"`
		} `json:"data"`
	}
	if err := client.Get(ctx, fmt.Sprintf("s/%s/stat/device", site), nil, &response); err != nil {
		return nil, err
	}
	current := map[int]map[string]json.RawMessage{}
	found := false
	for _, entry := range response.Data {
		if entry.ID != device.ID {
			continue
		}
		found = true
		for _, port := range entry.Ports {
			var number int
			if err := json.Unmarshal(port["port_idx"], &number); err != nil {
				return nil, fmt.Errorf("invalid current port identity: %w", err)
			}
			if _, duplicate := current[number]; duplicate {
				return nil, fmt.Errorf("duplicate current port %d", number)
			}
			current[number] = port
		}
	}
	if !found {
		return nil, fmt.Errorf("device %q absent from port snapshot; refusing update", device.ID)
	}
	for _, desired := range device.PortOverrides {
		preserved := current[desired.PortIDX]
		if preserved == nil {
			preserved = map[string]json.RawMessage{}
		}
		encoded, err := json.Marshal(desired)
		if err != nil {
			return nil, err
		}
		var overlay map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &overlay); err != nil {
			return nil, err
		}
		// These optional non-computed attributes are owned even when empty. Remove
		// their old values before overlaying so profile/name/LAG removal is effective.
		for _, key := range []string{"name", "portconf_id", "op_mode", "poe_mode", "aggregate_members"} {
			delete(preserved, key)
		}
		// Computed state is not ownership. Omitted exclusions must retain the fresh
		// snapshot, especially on initial management when no prior state exists.
		delete(overlay, "excluded_networkconf_ids")
		for key, value := range overlay {
			preserved[key] = value
		}
		if configuredExclusions[desired.PortIDX] {
			exclusions := desired.ExcludedNetworkIDs
			if exclusions == nil {
				exclusions = []string{}
			}
			encodedExclusions, err := json.Marshal(exclusions)
			if err != nil {
				return nil, err
			}
			preserved["excluded_networkconf_ids"] = encodedExclusions
		}
		result = append(result, preserved)
	}
	return result, nil
}
