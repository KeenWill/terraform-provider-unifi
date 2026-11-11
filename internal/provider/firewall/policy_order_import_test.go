package firewall

import (
	"context"
	"testing"

	"github.com/filipowm/go-unifi/unifi"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/stretchr/testify/require"

	"github.com/filipowm/terraform-provider-unifi/internal/provider/base"
)

type orderImportClient struct {
	unifi.Client
	calls int
	site  string
}

func (c *orderImportClient) ListFirewallZonePolicy(_ context.Context, site string) ([]unifi.FirewallZonePolicy, error) {
	c.calls++
	c.site = site
	return nil, nil
}

func TestPolicyOrderThreeSegmentImport(t *testing.T) {
	for _, id := range []string{"default:source:destination", "default:source", "default:source:destination:extra", "default::destination", "../default:source:destination"} {
		t.Run(id, func(t *testing.T) {
			ctx := context.Background()
			r := NewFirewallZonePolicyOrderResource().(*firewallZonePolicyOrderResource)
			client := &orderImportClient{}
			r.SetClient(&base.Client{Client: client})
			var definition resource.SchemaResponse
			r.Schema(ctx, resource.SchemaRequest{}, &definition)
			resp := resource.ImportStateResponse{State: tfsdk.State{Schema: definition.Schema}}
			r.ImportState(ctx, resource.ImportStateRequest{ID: id}, &resp)
			if id != "default:source:destination" {
				require.True(t, resp.Diagnostics.HasError())
				require.Zero(t, client.calls)
				return
			}
			require.False(t, resp.Diagnostics.HasError(), "%v", resp.Diagnostics)
			require.Equal(t, "default", client.site)
			require.Equal(t, 1, client.calls)
			var model FirewallZonePolicyOrderModel
			require.False(t, resp.State.Get(ctx, &model).HasError())
			require.Equal(t, "source", model.SourceZoneID.ValueString())
			require.Equal(t, "destination", model.DestinationZoneID.ValueString())
			require.Equal(t, "source:destination", model.ID.ValueString())
		})
	}
}
