package settings

import (
	"context"
	"errors"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/filipowm/terraform-provider-unifi/internal/client/legacy"
	"github.com/filipowm/terraform-provider-unifi/internal/provider/base"
	ut "github.com/filipowm/terraform-provider-unifi/internal/provider/types"
)

type teleportEnabledModel struct {
	base.Model
	Value types.Bool `tfsdk:"enabled"`
}

func (m *teleportEnabledModel) AsUnifiModel(_ context.Context) (interface{}, diag.Diagnostics) {
	return legacy.SecuritySettingValue{ID: m.ID.ValueString(), Enabled: m.Value.ValueBool()}, nil
}

func (m *teleportEnabledModel) Merge(_ context.Context, other interface{}) diag.Diagnostics {
	value, ok := other.(legacy.SecuritySettingValue)
	if !ok {
		return diag.Diagnostics{diag.NewErrorDiagnostic("Invalid security setting", "Unexpected security setting model")}
	}
	m.ID = types.StringValue(value.ID)
	m.Value = types.BoolValue(value.Enabled)
	return nil
}

type teleportEnabledResource struct {
	*base.GenericResource[*teleportEnabledModel]
}

func (r *teleportEnabledResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages only the enabled field of the Teleport singleton through the legacy API. Preserves all other settings. Do not combine with the full unifi_setting_teleport resource for the same site. Destroy relinquishes ownership without changing the controller. Import uses site:setting-id; no backend migration is performed.",
		Attributes:          map[string]schema.Attribute{"id": ut.ID(), "site": ut.SiteAttribute(), "enabled": schema.BoolAttribute{MarkdownDescription: "Whether Teleport remote access is enabled. Set to `false` to disable Teleport while preserving its subnet and all other settings.", Required: true}},
	}
}

func NewTeleportEnabledResource() resource.Resource {
	updater := func(ctx context.Context, client *base.Client, site string, body interface{}) (interface{}, error) {
		value, ok := body.(legacy.SecuritySettingValue)
		if !ok {
			return nil, errors.New("unexpected security setting model")
		}
		return client.UpdateSecuritySetting(ctx, site, legacy.TeleportEnabledSetting, value)
	}
	return &teleportEnabledResource{base.NewGenericResource("unifi_setting_teleport_enabled", func() *teleportEnabledModel { return &teleportEnabledModel{} }, base.ResourceFunctions{
		Read: func(ctx context.Context, client *base.Client, site, id string) (interface{}, error) {
			value, err := legacy.ReadSecuritySetting(ctx, client, site, legacy.TeleportEnabledSetting)
			if err == nil && id != "" && id != value.ID {
				return nil, errors.New("security setting identity changed; refusing to adopt another object")
			}
			return value, err
		}, Create: updater, Update: updater,
	})}
}
