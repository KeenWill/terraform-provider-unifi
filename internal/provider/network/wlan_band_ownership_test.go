package network

import (
	"encoding/json"
	"testing"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/go-version"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/stretchr/testify/require"

	"github.com/filipowm/terraform-provider-unifi/internal/provider/base"
)

func TestWLANUpdateBandOwnership(t *testing.T) {
	for _, test := range []struct {
		name           string
		config         map[string]cty.Value
		legacy, modern bool
	}{
		{"omitted bands preserve controller defaults", map[string]cty.Value{}, false, false},
		{"explicit legacy band", map[string]cty.Value{"wlan_band": cty.StringVal("5g")}, true, false},
		{"explicit modern bands", map[string]cty.Value{"wlan_bands": cty.SetVal([]cty.Value{cty.StringVal("5g"), cty.StringVal("6g")})}, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := ResourceWLAN()
			test.config["name"] = cty.StringVal("renamed")
			test.config["security"] = cty.StringVal("open")
			test.config["user_group_id"] = cty.StringVal("fixture-group")
			raw, err := r.CoreConfigSchema().CoerceValue(cty.ObjectVal(test.config))
			require.NoError(t, err)
			d := r.Data(&terraform.InstanceState{ID: "fixture", Attributes: map[string]string{}, RawConfig: raw})
			require.NoError(t, d.Set("name", "renamed"))
			require.NoError(t, d.Set("security", "open"))
			require.NoError(t, d.Set("wlan_band", "5g"))
			require.NoError(t, d.Set("wlan_bands", []string{"5g", "6g"}))
			model, err := resourceWLANGetResourceData(d, &base.Client{Version: version.Must(version.NewVersion("11.0.99"))})
			require.NoError(t, err)
			encoded, err := json.Marshal(model)
			require.NoError(t, err)
			var wire map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(encoded, &wire))
			_, legacy := wire["wlan_band"]
			_, modern := wire["wlan_bands"]
			require.Equal(t, test.legacy, legacy)
			require.Equal(t, test.modern, modern)
			if modern {
				var bands []string
				require.NoError(t, json.Unmarshal(wire["wlan_bands"], &bands))
				require.ElementsMatch(t, []string{"5g", "6g"}, bands)
			}
		})
	}
}
