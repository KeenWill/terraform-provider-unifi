package network

import (
	"context"
	"testing"

	"github.com/filipowm/terraform-provider-unifi/internal/provider/base"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/go-version"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/stretchr/testify/require"
)

func TestNetwork11MDNSMustUseGlobalScope(t *testing.T) {
	for _, tc := range []struct {
		version   string
		explicit  bool
		wantError bool
	}{
		{"11.0.99", true, true}, {"11.0.99", false, false}, {"10.6.106", true, false},
	} {
		t.Run(tc.version+"/"+map[bool]string{true: "declared", false: "omitted"}[tc.explicit], func(t *testing.T) {
			r := ResourceNetwork()
			values := map[string]cty.Value{"name": cty.StringVal("fixture"), "purpose": cty.StringVal("vlan-only")}
			if tc.explicit {
				values["multicast_dns"] = cty.BoolVal(false)
			}
			raw, err := r.CoreConfigSchema().CoerceValue(cty.ObjectVal(values))
			require.NoError(t, err)
			state := &terraform.InstanceState{Attributes: map[string]string{}, RawConfig: raw}
			_, err = r.Diff(context.Background(), state, terraform.NewResourceConfigShimmed(raw, r.CoreConfigSchema()), &base.Client{Version: version.Must(version.NewVersion(tc.version))})
			if tc.wantError {
				require.ErrorContains(t, err, "unifi_setting_mdns_scope")
			} else {
				require.NoError(t, err)
			}
		})
	}
}
