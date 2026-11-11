package legacy

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
)

// RequireNetwork11Schema reads the controller version immediately before a
// private mutation. A cached provider version cannot authorize a later upgrade.
func RequireNetwork11Schema(ctx context.Context, client DeviceTransport, site string) error {
	prefix, err := securitySettingPath(site)
	if err != nil {
		return err
	}
	var response struct {
		Data []struct {
			Version string `json:"version"`
		} `json:"data"`
	}
	if err := client.Get(ctx, prefix+"/stat/sysinfo", nil, &response); err != nil {
		return errors.New("cannot verify private API schema version")
	}
	if len(response.Data) != 1 || response.Data[0].Version != "11.0.99" {
		return errors.New("private write refused: only acceptance-tested Network 11.0.99 is supported")
	}
	return nil
}

type MDNSScope struct {
	ID         string
	Scope      string
	NetworkIDs []string
}

func mdnsPath(site string) (string, error) {
	if _, err := securitySettingPath(site); err != nil {
		return "", err
	}
	return "/proxy/network/v2/api/site/" + site + "/global/config/network", nil
}

func validMDNSScope(value MDNSScope) error {
	if value.Scope != "all" && value.Scope != "none" && value.Scope != "some" {
		return errors.New("unknown mDNS scope")
	}
	if value.Scope == "some" && len(value.NetworkIDs) == 0 {
		return errors.New("some scope requires network IDs")
	}
	seen := map[string]bool{}
	for _, id := range value.NetworkIDs {
		if id == "" || strings.ContainsAny(id, "/\\?#%:\x00\r\n") || strings.TrimSpace(id) != id || seen[id] {
			return errors.New("invalid or duplicate mDNS network identity")
		}
		seen[id] = true
	}
	return nil
}

func ReadMDNSScope(ctx context.Context, client DeviceTransport, site string) (MDNSScope, error) {
	value := MDNSScope{ID: "mdns-scope"}
	path, err := mdnsPath(site)
	if err != nil {
		return value, err
	}
	var response map[string]json.RawMessage
	if err := client.Get(ctx, path, nil, &response); err != nil {
		return value, errors.New("cannot read global network mDNS scope")
	}
	if json.Unmarshal(response["mdns_enabled_for"], &value.Scope) != nil ||
		json.Unmarshal(response["mdns_enabled_for_network_ids"], &value.NetworkIDs) != nil ||
		string(response["mdns_enabled_for_network_ids"]) == "null" {
		return value, errors.New("unknown global network mDNS schema")
	}
	return value, validMDNSScope(value)
}

// UpdateMDNSScope writes the declared scope and, only for 'some', the declared
// network set. Service filters, security posture and other global fields never
// appear in this payload. Caller holds the site lock through verification.
func UpdateMDNSScope(ctx context.Context, client DeviceTransport, site string, desired MDNSScope) (MDNSScope, error) {
	if err := validMDNSScope(desired); err != nil {
		return MDNSScope{}, err
	}
	if desired.ID != "" && desired.ID != "mdns-scope" {
		return MDNSScope{}, errors.New("invalid mDNS singleton identity")
	}
	if err := RequireNetwork11Schema(ctx, client, site); err != nil {
		return MDNSScope{}, err
	}
	current, err := ReadMDNSScope(ctx, client, site)
	if err != nil {
		return current, err
	}
	payload := map[string]interface{}{"mdns_enabled_for": desired.Scope}
	if desired.Scope == "some" {
		payload["mdns_enabled_for_network_ids"] = desired.NetworkIDs
	}
	path, _ := mdnsPath(site)
	var response json.RawMessage
	if err := client.Put(ctx, path, payload, &response); err != nil {
		return current, errors.New("mDNS update failed; refresh before retrying")
	}
	persisted, err := ReadMDNSScope(ctx, client, site)
	if err != nil {
		return current, err
	}
	want, got := slices.Clone(desired.NetworkIDs), slices.Clone(persisted.NetworkIDs)
	slices.Sort(want)
	slices.Sort(got)
	if persisted.Scope != desired.Scope || (desired.Scope == "some" && !slices.Equal(want, got)) {
		return current, errors.New("mDNS readback did not confirm the declared scope")
	}
	return persisted, nil
}
