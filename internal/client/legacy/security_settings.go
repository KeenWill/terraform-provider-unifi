package legacy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// SecuritySetting selects a singleton; arbitrary settings and fields are not writable.
type SecuritySetting string

const (
	IPSModeSetting         SecuritySetting = "ips"
	TeleportEnabledSetting SecuritySetting = "teleport"
)

func (setting SecuritySetting) field() (string, error) {
	switch setting {
	case IPSModeSetting:
		return "ips_mode", nil
	case TeleportEnabledSetting:
		return "enabled", nil
	default:
		return "", errors.New("unsupported security setting")
	}
}

// SecuritySettingValue contains only the managed field, never the raw settings document.
type SecuritySettingValue struct {
	ID      string
	Mode    string
	Enabled bool
}

func securitySettingPath(site string) (string, error) {
	if site == "" || site == "." || site == ".." || strings.ContainsAny(site, "/\\?#%") {
		return "", errors.New("invalid legacy site reference")
	}
	return "s/" + site, nil
}

func readSecuritySetting(ctx context.Context, client DeviceTransport, site string, setting SecuritySetting) (map[string]json.RawMessage, SecuritySettingValue, error) {
	var value SecuritySettingValue
	if _, err := setting.field(); err != nil {
		return nil, value, err
	}
	prefix, err := securitySettingPath(site)
	if err != nil {
		return nil, value, err
	}
	var response struct {
		Data []map[string]json.RawMessage `json:"data"`
	}
	if err := client.Get(ctx, prefix+"/get/setting", nil, &response); err != nil {
		return nil, value, errors.New("security setting read failed")
	}
	var found map[string]json.RawMessage
	for _, candidate := range response.Data {
		var key string
		if err := json.Unmarshal(candidate["key"], &key); err != nil {
			return nil, value, errors.New("invalid setting key")
		}
		if key == string(setting) {
			if found != nil {
				return nil, value, errors.New("ambiguous security setting")
			}
			found = candidate
		}
	}
	if found == nil {
		return nil, value, errors.New("security setting absent; refusing to forget or create it")
	}
	if err := json.Unmarshal(found["_id"], &value.ID); err != nil || value.ID == "" {
		return nil, value, errors.New("missing security setting identity")
	}
	field, _ := setting.field()
	raw := found[field]
	if string(raw) == "null" {
		return nil, value, errors.New("null security setting value")
	}
	if setting == IPSModeSetting {
		if err := json.Unmarshal(raw, &value.Mode); err != nil {
			return nil, value, errors.New("invalid IPS mode")
		}
		switch value.Mode {
		case "ids", "ips", "ipsInline", "disabled":
		default:
			return nil, value, errors.New("unsupported IPS mode")
		}
	} else if err := json.Unmarshal(raw, &value.Enabled); err != nil {
		return nil, value, errors.New("invalid Teleport enabled value")
	}
	return found, value, nil
}

// ReadSecuritySetting fails closed on absent, ambiguous or malformed singleton settings.
func ReadSecuritySetting(ctx context.Context, client DeviceTransport, site string, setting SecuritySetting) (SecuritySettingValue, error) {
	_, value, err := readSecuritySetting(ctx, client, site, setting)
	return value, err
}

// UpdateSecuritySetting overlays one field on a fresh snapshot. Caller must hold
// the site/setting lock across this operation; separate processes require exclusion.
func UpdateSecuritySetting(ctx context.Context, client DeviceTransport, site string, setting SecuritySetting, desired SecuritySettingValue) (SecuritySettingValue, error) {
	current, value, err := readSecuritySetting(ctx, client, site, setting)
	if err != nil {
		return value, err
	}
	if desired.ID != "" && desired.ID != value.ID {
		return value, errors.New("security setting identity changed; refusing update")
	}
	field, _ := setting.field()
	var encoded []byte
	if setting == IPSModeSetting {
		switch desired.Mode {
		case "ids", "ips", "disabled":
		default:
			return value, errors.New("unsupported IPS mode")
		}
		if value.Mode == desired.Mode {
			return value, nil
		}
		encoded, err = json.Marshal(desired.Mode)
	} else {
		if value.Enabled == desired.Enabled {
			return value, nil
		}
		encoded, err = json.Marshal(desired.Enabled)
	}
	if err != nil {
		return value, errors.New("cannot encode security setting")
	}
	current[field] = encoded
	prefix, _ := securitySettingPath(site)
	var response json.RawMessage
	if err := client.Put(ctx, prefix+"/set/setting/"+string(setting), current, &response); err != nil {
		return value, errors.New("security setting update failed; refresh before retrying")
	}
	persisted, err := ReadSecuritySetting(ctx, client, site, setting)
	if err != nil {
		return value, err
	}
	if persisted.ID != value.ID || (setting == IPSModeSetting && persisted.Mode != desired.Mode) || (setting == TeleportEnabledSetting && persisted.Enabled != desired.Enabled) {
		return value, fmt.Errorf("security setting %s readback did not confirm the requested value", setting)
	}
	return persisted, nil
}
