package network

import (
	"context"
	"testing"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/stretchr/testify/require"
)

func TestVPNClientValidationDefersUnknownPurposeAndType(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		purpose cty.Value
		vpnType cty.Value
		wantErr bool
	}{
		{"unknown purpose", cty.UnknownVal(cty.String), cty.StringVal("wireguard-client"), false},
		{"unknown VPN type", cty.StringVal("vpn-client"), cty.UnknownVal(cty.String), false},
		{"known valid VPN", cty.StringVal("vpn-client"), cty.StringVal("wireguard-client"), false},
		{"known missing type", cty.StringVal("vpn-client"), cty.NullVal(cty.String), true},
		{"known non-VPN purpose", cty.StringVal("corporate"), cty.StringVal("wireguard-client"), true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			resource := ResourceNetwork()
			config, err := resource.CoreConfigSchema().CoerceValue(cty.ObjectVal(map[string]cty.Value{
				"name": cty.StringVal("fixture-vpn"), "purpose": testCase.purpose, "vpn_type": testCase.vpnType,
				"subnet": cty.StringVal("192.0.2.2/32"), "dhcp_dns": cty.ListVal([]cty.Value{cty.StringVal("192.0.2.1")}),
				"wireguard_client_peer_ip":         cty.StringVal("198.51.100.1"),
				"wireguard_client_peer_port":       cty.NumberIntVal(51820),
				"wireguard_client_peer_public_key": cty.StringVal("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
			}))
			require.NoError(t, err)
			state := &terraform.InstanceState{Attributes: map[string]string{}, RawConfig: config}
			_, err = resource.Diff(context.Background(), state, terraform.NewResourceConfigShimmed(config, resource.CoreConfigSchema()), nil)
			if testCase.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
