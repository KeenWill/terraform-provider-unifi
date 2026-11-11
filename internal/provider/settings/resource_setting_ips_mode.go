package settings

import (
	"context"
	"errors"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/filipowm/terraform-provider-unifi/internal/client/legacy"
	"github.com/filipowm/terraform-provider-unifi/internal/provider/base"
	ut "github.com/filipowm/terraform-provider-unifi/internal/provider/types"
)

type ipsModeModel struct {
	base.Model
	Value types.String `tfsdk:"ips_mode"`
}

func (m *ipsModeModel) AsUnifiModel(_ context.Context) (interface{}, diag.Diagnostics) {
	return legacy.SecuritySettingValue{ID: m.ID.ValueString(), Mode: m.Value.ValueString()}, nil
}

func (m *ipsModeModel) Merge(_ context.Context, other interface{}) diag.Diagnostics {
	value, ok := other.(legacy.SecuritySettingValue)
	if !ok {
		return diag.Diagnostics{diag.NewErrorDiagnostic("Invalid security setting", "Unexpected security setting model")}
	}
	m.ID = types.StringValue(value.ID)
	m.Value = types.StringValue(value.Mode)
	return nil
}

type ipsModeResource struct {
	*base.GenericResource[*ipsModeModel]
}

func (r *ipsModeResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages only the ips_mode field of the IPS singleton through the legacy API. Preserves all other settings. Do not combine with the full unifi_setting_ips resource for the same site. Destroy relinquishes ownership without changing the controller. Import uses site:setting-id; no backend migration is performed.",
		Attributes:          map[string]schema.Attribute{"id": ut.ID(), "site": ut.SiteAttribute(), "ips_mode": schema.StringAttribute{MarkdownDescription: "Detection mode: `ids` notifies, `ips` notifies and blocks, and `disabled` disables inspection. Preserves network and category selections. Existing `ipsInline` values can be read and migrated, but cannot be configured here.", Required: true, Validators: []validator.String{stringvalidator.OneOf("ids", "ips", "disabled")}}},
	}
}

func NewIpsModeResource() resource.Resource {
	updater := func(ctx context.Context, client *base.Client, site string, body interface{}) (interface{}, error) {
		value, ok := body.(legacy.SecuritySettingValue)
		if !ok {
			return nil, errors.New("unexpected security setting model")
		}
		return client.UpdateSecuritySetting(ctx, site, legacy.IPSModeSetting, value)
	}
	return &ipsModeResource{base.NewGenericResource("unifi_setting_ips_mode", func() *ipsModeModel { return &ipsModeModel{} }, base.ResourceFunctions{
		Read: func(ctx context.Context, client *base.Client, site, id string) (interface{}, error) {
			value, err := legacy.ReadSecuritySetting(ctx, client, site, legacy.IPSModeSetting)
			if err == nil && id != "" && id != value.ID {
				return nil, errors.New("security setting identity changed; refusing to adopt another object")
			}
			return value, err
		}, Create: updater, Update: updater,
	})}
}
