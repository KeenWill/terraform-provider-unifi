package settings

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/filipowm/go-unifi/unifi"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/stretchr/testify/require"

	"github.com/filipowm/terraform-provider-unifi/internal/provider/base"
)

type securitySettingsReadClient struct {
	unifi.Client
	fixture []byte
	reads   int
}

func (c *securitySettingsReadClient) Get(_ context.Context, _ string, _, response interface{}) error {
	c.reads++
	return json.Unmarshal(c.fixture, response)
}

func TestNarrowSettingsImportChecksIdentityAndDestroyDoesNotWrite(t *testing.T) {
	fixture, err := os.ReadFile("../../client/legacy/testdata/security-settings.json")
	require.NoError(t, err)
	for _, test := range []struct {
		name    string
		id      string
		factory func() resource.Resource
	}{
		{"IPS mode", "ips-fixture-id", NewIpsModeResource},
		{"Teleport enabled", "teleport-fixture-id", NewTeleportEnabledResource},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, valid := range []bool{true, false} {
				client := &securitySettingsReadClient{fixture: fixture}
				instance := test.factory()
				configurable, ok := instance.(resource.ResourceWithConfigure)
				require.True(t, ok)
				configureResponse := resource.ConfigureResponse{}
				configurable.Configure(t.Context(), resource.ConfigureRequest{ProviderData: &base.Client{Client: client, Site: "default"}}, &configureResponse)
				require.False(t, configureResponse.Diagnostics.HasError())
				var schemaResponse resource.SchemaResponse
				instance.Schema(t.Context(), resource.SchemaRequest{}, &schemaResponse)
				state := tfsdk.State{Schema: schemaResponse.Schema, Raw: tftypes.NewValue(schemaResponse.Schema.Type().TerraformType(t.Context()), nil)}
				response := resource.ImportStateResponse{State: state}
				importer, ok := instance.(resource.ResourceWithImportState)
				require.True(t, ok)
				identifier := test.id
				if !valid {
					identifier = "foreign-id"
				}
				importer.ImportState(t.Context(), resource.ImportStateRequest{ID: "default:" + identifier}, &response)
				require.Equal(t, !valid, response.Diagnostics.HasError())
				require.Equal(t, 1, client.reads)
				if valid {
					var deleted resource.DeleteResponse
					instance.Delete(t.Context(), resource.DeleteRequest{State: response.State}, &deleted)
					require.False(t, deleted.Diagnostics.HasError())
					require.Equal(t, 1, client.reads, "destroy must only relinquish ownership")
				}
			}
		})
	}
}
