package firewall

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/filipowm/go-unifi/unifi"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/require"
)

func TestOrderingPayloadPreservesPriorityAndEncodesUnusedSideAsArray(t *testing.T) {
	ctx := context.Background()
	model := FirewallZonePolicyOrderModel{
		SourceZoneID:        types.StringValue("vpn"),
		DestinationZoneID:   types.StringValue("gateway"),
		BeforePredefinedIDs: mustStringList(ctx, t, "replies", "dns", "admin", "ospf", "block"),
		AfterPredefinedIDs:  types.ListNull(types.StringType),
	}
	payload, diagnostics := model.AsUnifiModel(ctx)
	require.False(t, diagnostics.HasError())
	encoded, err := json.Marshal(payload)
	require.NoError(t, err)
	require.JSONEq(t, `{
		"source_zone_id":"vpn", "destination_zone_id":"gateway",
		"before_predefined_ids":["replies","dns","admin","ospf","block"],
		"after_predefined_ids":[]
	}`, string(encoded))
}

func TestIncompleteReorderResponseCannotReportSuccess(t *testing.T) {
	require.Error(t, validateReorderResponse([]string{"allow", "block"}, nil))
	require.Error(t, validateReorderResponse([]string{"allow", "block"}, []unifi.FirewallZonePolicy{{ID: "allow"}}))
	require.NoError(t, validateReorderResponse([]string{"allow", "block"}, []unifi.FirewallZonePolicy{{ID: "allow"}, {ID: "unmanaged"}, {ID: "block"}}))
}
