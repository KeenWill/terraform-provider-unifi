package firewall

import (
	"context"
	"strings"

	"github.com/filipowm/terraform-provider-unifi/internal/client/integration"
	"github.com/filipowm/terraform-provider-unifi/internal/provider/base"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type flowReportingModel struct {
	ID       types.String `tfsdk:"id"`
	SiteID   types.String `tfsdk:"site_id"`
	PolicyID types.String `tfsdk:"policy_id"`
	Enabled  types.Bool   `tfsdk:"enabled"`
}
type flowReportingResource struct{ client *integration.Client }

func NewFlowReportingResource() resource.Resource { return &flowReportingResource{} }
func (r *flowReportingResource) Metadata(_ context.Context, _ resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "unifi_firewall_policy_flow_reporting"
}
func (r *flowReportingResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{MarkdownDescription: "Owns only flow reporting on an existing user-defined firewall policy through the official Network Integration API. Requires an API key and explicit official API UUIDs; legacy IDs and provider site names are not interchangeable. Qualified for Network 11.0.99. Destroy relinquishes ownership without changing the policy. Do not concurrently manage this field through another resource or UI. Import uses `official-site-uuid/official-policy-uuid`.", Attributes: map[string]schema.Attribute{
		"id":        schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
		"site_id":   schema.StringAttribute{Required: true, MarkdownDescription: "Official Integration API site UUID.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"policy_id": schema.StringAttribute{Required: true, MarkdownDescription: "Official Integration API user-defined policy UUID.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"enabled":   schema.BoolAttribute{Required: true, MarkdownDescription: "Whether matching traffic appears in Insights Flows."},
	}}
}
func (r *flowReportingResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*base.Client)
	if !ok {
		resp.Diagnostics.AddError("Invalid provider client", "Expected UniFi client")
		return
	}
	var err error
	r.client, err = c.IntegrationClient()
	if err != nil {
		resp.Diagnostics.AddError("API key required", err.Error())
	}
}
func validFlowIDs(m flowReportingModel) bool {
	_, a := uuid.Parse(m.SiteID.ValueString())
	_, b := uuid.Parse(m.PolicyID.ValueString())
	return a == nil && b == nil
}
func (r *flowReportingResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m flowReportingModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !validFlowIDs(m) {
		resp.Diagnostics.AddError("Invalid official IDs", "site_id and policy_id must be official API UUIDs")
		return
	}
	p, err := r.client.FlowPolicy(ctx, integration.SiteID(m.SiteID.ValueString()), integration.ObjectID(m.PolicyID.ValueString()))
	if err != nil {
		resp.Diagnostics.AddError("Read flow reporting failed", err.Error())
		return
	}
	m.Enabled = types.BoolValue(p.Enabled)
	m.ID = types.StringValue(m.SiteID.ValueString() + "/" + m.PolicyID.ValueString())
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
func (r *flowReportingResource) apply(ctx context.Context, m *flowReportingModel) error {
	_, err := r.client.SetFlowReporting(ctx, integration.SiteID(m.SiteID.ValueString()), integration.ObjectID(m.PolicyID.ValueString()), m.Enabled.ValueBool())
	if err == nil {
		m.ID = types.StringValue(m.SiteID.ValueString() + "/" + m.PolicyID.ValueString())
	}
	return err
}
func (r *flowReportingResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m flowReportingModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !validFlowIDs(m) {
		resp.Diagnostics.AddError("Invalid official IDs", "site_id and policy_id must be official API UUIDs")
		return
	}
	if err := r.apply(ctx, &m); err != nil {
		resp.Diagnostics.AddError("Set flow reporting failed", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
func (r *flowReportingResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var m flowReportingModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !validFlowIDs(m) {
		resp.Diagnostics.AddError("Invalid official IDs", "site_id and policy_id must be official API UUIDs")
		return
	}
	if err := r.apply(ctx, &m); err != nil {
		resp.Diagnostics.AddError("Set flow reporting failed", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
func (r *flowReportingResource) Delete(context.Context, resource.DeleteRequest, *resource.DeleteResponse) {
}
func (r *flowReportingResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.Split(req.ID, "/")
	if len(parts) != 2 {
		resp.Diagnostics.AddError("Invalid import", "Expected official-site-uuid/official-policy-uuid")
		return
	}
	m := flowReportingModel{ID: types.StringValue(req.ID), SiteID: types.StringValue(parts[0]), PolicyID: types.StringValue(parts[1]), Enabled: types.BoolNull()}
	if !validFlowIDs(m) {
		resp.Diagnostics.AddError("Invalid import", "Both identities must be official API UUIDs")
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
