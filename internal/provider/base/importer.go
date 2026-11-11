package base

import (
	"context"
	"errors"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// for Terraform Plugin SDK v2.
func ImportSiteAndID(_ context.Context, d *schema.ResourceData, _ interface{}) ([]*schema.ResourceData, error) {
	site, id, err := parseLegacyImport(d.Id(), false)
	if err != nil {
		return nil, err
	}
	if site != "" {
		if err := d.Set("site", site); err != nil {
			return nil, err
		}
	}
	d.SetId(id)
	return []*schema.ResourceData{d}, nil
}

// for Terraform Plugin Framework.
func ImportIDWithSite(req resource.ImportStateRequest, resp *resource.ImportStateResponse) (string, string) {
	site, id, err := parseLegacyImport(req.ID, true)
	if err != nil {
		resp.Diagnostics.AddError("Invalid ID", err.Error())
		return "", ""
	}
	return id, site
}

// Legacy IDs remain opaque: Mongo IDs, UUIDs and future identifiers are valid.
// A UUID here still belongs to the legacy backend; it is not an Integration ID.
func parseLegacyImport(value string, requireSite bool) (string, string, error) {
	parts := strings.Split(value, ":")
	if len(parts) > 2 || (requireSite && len(parts) != 2) {
		return "", "", errors.New("expected legacy import in site:id format")
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.TrimSpace(part) != part || strings.ContainsAny(part, "/\\?#%\x00\r\n") {
			return "", "", errors.New("legacy import contains an empty or unsafe identity segment")
		}
	}
	if len(parts) == 1 {
		return "", parts[0], nil
	}
	return parts[0], parts[1], nil
}
