package legacy

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

type settingsFixtureTransport struct {
	document  map[string]interface{}
	writes    int
	failRead  bool
	failWrite bool
	stale     bool
}

func newSettingsFixture(t *testing.T) *settingsFixtureTransport {
	t.Helper()
	data, err := os.ReadFile("testdata/security-settings.json")
	require.NoError(t, err)
	fixture := &settingsFixtureTransport{}
	require.NoError(t, json.Unmarshal(data, &fixture.document))
	return fixture
}

func (f *settingsFixtureTransport) Get(_ context.Context, path string, _ interface{}, response interface{}) error {
	if f.failRead {
		return errors.New("sensitive read failure")
	}
	if path != "s/default/get/setting" {
		return errors.New("unexpected path")
	}
	encoded, err := json.Marshal(f.document)
	if err != nil {
		return err
	}
	return json.Unmarshal(encoded, response)
}

func (f *settingsFixtureTransport) Put(_ context.Context, path string, request, _ interface{}) error {
	f.writes++
	if f.failWrite {
		return errors.New("sensitive write failure")
	}
	if f.stale {
		return nil
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return err
	}
	var updated map[string]interface{}
	if err := json.Unmarshal(encoded, &updated); err != nil {
		return err
	}
	key, ok := updated["key"].(string)
	if !ok {
		return errors.New("invalid fixture key")
	}
	if path != "s/default/set/setting/"+key {
		return errors.New("unexpected path")
	}
	entries, ok := f.document["data"].([]interface{})
	if !ok {
		return errors.New("invalid fixture data")
	}
	for index, entry := range entries {
		candidate, ok := entry.(map[string]interface{})
		if !ok {
			return errors.New("invalid fixture entry")
		}
		if candidate["key"] == updated["key"] {
			entries[index] = updated
		}
	}
	return nil
}

func TestSecuritySettingPreservesEveryUnownedField(t *testing.T) {
	for _, setting := range []SecuritySetting{IPSModeSetting, TeleportEnabledSetting} {
		t.Run(string(setting), func(t *testing.T) {
			fixture := newSettingsFixture(t)
			before, _, err := readSecuritySetting(context.Background(), fixture, "default", setting)
			require.NoError(t, err)
			desired := SecuritySettingValue{Mode: "ips", Enabled: false}
			result, err := UpdateSecuritySetting(context.Background(), fixture, "default", setting, desired)
			require.NoError(t, err)
			require.NotEmpty(t, result.ID)
			after, _, err := readSecuritySetting(context.Background(), fixture, "default", setting)
			require.NoError(t, err)
			field, err := setting.field()
			require.NoError(t, err)
			delete(before, field)
			delete(after, field)
			require.Equal(t, before, after)
			require.Equal(t, 1, fixture.writes)
			_, err = UpdateSecuritySetting(context.Background(), fixture, "default", setting, desired)
			require.NoError(t, err)
			require.Equal(t, 1, fixture.writes, "no-op must not PUT")
		})
	}
}

func TestSecuritySettingFailsClosed(t *testing.T) {
	for _, scenario := range []string{"absent", "duplicate", "null", "missing", "wrong_type", "identity", "auth", "write", "stale", "bad_site", "bad_mode", "bad_setting"} {
		t.Run(scenario, func(t *testing.T) {
			fixture := newSettingsFixture(t)
			entries, ok := fixture.document["data"].([]interface{})
			require.True(t, ok)
			first, ok := entries[0].(map[string]interface{})
			require.True(t, ok)
			desired := SecuritySettingValue{Mode: "ips"}
			site, setting := "default", IPSModeSetting
			switch scenario {
			case "absent":
				fixture.document["data"] = []interface{}{}
			case "duplicate":
				fixture.document["data"] = append(entries, first)
			case "null":
				first["ips_mode"] = nil
			case "missing":
				delete(first, "ips_mode")
			case "wrong_type":
				first["ips_mode"] = false
			case "identity":
				desired.ID = "other-id"
			case "auth":
				fixture.failRead = true
			case "write":
				fixture.failWrite = true
			case "stale":
				fixture.stale = true
			case "bad_site":
				site = "../default"
			case "bad_mode":
				desired.Mode = "preset"
			case "bad_setting":
				setting = "other"
			}
			_, err := UpdateSecuritySetting(context.Background(), fixture, site, setting, desired)
			require.Error(t, err)
			require.NotContains(t, err.Error(), "sensitive")
			if scenario == "write" || scenario == "stale" {
				require.Equal(t, 1, fixture.writes)
			} else {
				require.Zero(t, fixture.writes)
			}
		})
	}
}

func TestSecuritySettingMigratesExistingInlineMode(t *testing.T) {
	fixture := newSettingsFixture(t)
	entries, ok := fixture.document["data"].([]interface{})
	require.True(t, ok)
	ips, ok := entries[0].(map[string]interface{})
	require.True(t, ok)
	ips["ips_mode"] = "ipsInline"
	current, err := ReadSecuritySetting(t.Context(), fixture, "default", IPSModeSetting)
	require.NoError(t, err)
	require.Equal(t, "ipsInline", current.Mode)
	updated, err := UpdateSecuritySetting(t.Context(), fixture, "default", IPSModeSetting, SecuritySettingValue{ID: current.ID, Mode: "ips"})
	require.NoError(t, err)
	require.Equal(t, "ips", updated.Mode)
	require.Equal(t, current.ID, updated.ID)
	require.Equal(t, 1, fixture.writes)
	_, err = UpdateSecuritySetting(t.Context(), fixture, "default", IPSModeSetting, SecuritySettingValue{Mode: "ipsInline"})
	require.Error(t, err)
	require.Equal(t, 1, fixture.writes)
}
