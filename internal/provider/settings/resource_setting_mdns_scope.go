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

type mdnsScopeModel struct {
	base.Model
	Scope      types.String `tfsdk:"scope"`
	NetworkIDs types.Set    `tfsdk:"network_ids"`
}

func (m *mdnsScopeModel) AsUnifiModel(ctx context.Context) (interface{}, diag.Diagnostics) {
	value := legacy.MDNSScope{ID: m.ID.ValueString(), Scope: m.Scope.ValueString()}
	var diagnostics diag.Diagnostics
	if value.Scope == "some" {
		diagnostics.Append(m.NetworkIDs.ElementsAs(ctx, &value.NetworkIDs, false)...)
	}
	return value, diagnostics
}
func (m *mdnsScopeModel) Merge(ctx context.Context, other interface{}) diag.Diagnostics {
	value, ok := other.(legacy.MDNSScope)
	if !ok {
		return diag.Diagnostics{diag.NewErrorDiagnostic("Invalid mDNS scope", "Unexpected controller response type")}
	}
	m.ID = types.StringValue(value.ID)
	m.Scope = types.StringValue(value.Scope)
	var diagnostics diag.Diagnostics
	m.NetworkIDs, diagnostics = types.SetValueFrom(ctx, types.StringType, value.NetworkIDs)
	return diagnostics
}

type mdnsScopeResource struct {
	*base.GenericResource[*mdnsScopeModel]
}

var _ resource.ResourceWithValidateConfig = (*mdnsScopeResource)(nil)

func (r *mdnsScopeResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{MarkdownDescription: "Manages global mDNS network scope on UniFi OS Network 11.0.99. Writes only scope and explicitly selected networks, preserving service filters and other global settings. Unknown application versions refuse writes. Destroy relinquishes ownership without changing the controller. Import uses `site:mdns-scope`. Do not manage this singleton from multiple provider processes.", Attributes: map[string]schema.Attribute{
		"id": ut.ID(), "site": ut.SiteAttribute(),
		"scope":       schema.StringAttribute{MarkdownDescription: "Networks participating in mDNS: `all`, `none`, or `some`.", Required: true, Validators: []validator.String{stringvalidator.OneOf("all", "none", "some")}},
		"network_ids": schema.SetAttribute{MarkdownDescription: "Declare a nonempty set for `some`. Omit for `all` or `none`; the controller-derived set is then read-only.", Optional: true, Computed: true, ElementType: types.StringType},
	}}
}
func (r *mdnsScopeResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config mdnsScopeModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() || config.Scope.IsUnknown() || config.Scope.IsNull() {
		return
	}
	if config.Scope.ValueString() == "some" {
		if config.NetworkIDs.IsNull() || (!config.NetworkIDs.IsUnknown() && len(config.NetworkIDs.Elements()) == 0) {
			resp.Diagnostics.AddError("Missing mDNS networks", "scope = some requires a nonempty network_ids set")
		}
	} else if !config.NetworkIDs.IsNull() && !config.NetworkIDs.IsUnknown() {
		resp.Diagnostics.AddError("Unexpected mDNS networks", "Omit network_ids when scope is all or none")
	}
}
func NewMDNSScopeResource() resource.Resource {
	r := &mdnsScopeResource{}
	update := func(ctx context.Context, c *base.Client, site string, body interface{}) (interface{}, error) {
		value, ok := body.(legacy.MDNSScope)
		if !ok {
			return nil, errors.New("invalid mDNS scope model")
		}
		return c.UpdateMDNSScope(ctx, site, value)
	}
	r.GenericResource = base.NewGenericResource("unifi_setting_mdns_scope", func() *mdnsScopeModel { return &mdnsScopeModel{} }, base.ResourceFunctions{
		Read: func(ctx context.Context, c *base.Client, site, id string) (interface{}, error) {
			if id != "mdns-scope" {
				return nil, errors.New("import requires site:mdns-scope")
			}
			return legacy.ReadMDNSScope(ctx, c, site)
		}, Create: update, Update: update,
	})
	return r
}
