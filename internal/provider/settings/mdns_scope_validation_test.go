package settings

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/stretchr/testify/require"
)

func TestMDNSScopeValidation(t *testing.T) {
	r := NewMDNSScopeResource().(*mdnsScopeResource)
	var schema resource.SchemaResponse
	r.Schema(t.Context(), resource.SchemaRequest{}, &schema)
	setType := tftypes.Set{ElementType: tftypes.String}
	for _, scope := range []string{"all", "none", "some"} {
		for _, test := range []struct {
			name  string
			value interface{}
		}{
			{"unknown", tftypes.UnknownValue},
			{"resolved-null", nil},
			{"empty", []tftypes.Value{}},
			{"selected", []tftypes.Value{tftypes.NewValue(tftypes.String, "network-id")}},
		} {
			t.Run(scope+"/"+test.name, func(t *testing.T) {
				config := tfsdk.Config{Schema: schema.Schema, Raw: tftypes.NewValue(schema.Schema.Type().TerraformType(t.Context()), map[string]tftypes.Value{
					"id": tftypes.NewValue(tftypes.String, nil), "site": tftypes.NewValue(tftypes.String, nil),
					"scope": tftypes.NewValue(tftypes.String, scope), "network_ids": tftypes.NewValue(setType, test.value),
				})}
				var response resource.ValidateConfigResponse
				r.ValidateConfig(t.Context(), resource.ValidateConfigRequest{Config: config}, &response)
				wantError := scope == "some" && (test.name == "resolved-null" || test.name == "empty") || scope != "some" && (test.name == "empty" || test.name == "selected")
				require.Equal(t, wantError, response.Diagnostics.HasError(), response.Diagnostics)
			})
		}
	}
}
