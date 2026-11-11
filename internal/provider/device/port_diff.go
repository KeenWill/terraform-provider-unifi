package device

import (
	"context"
	"fmt"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// Preserve controller defaults by port number before SDK set hashing. Hashing
// only the number loses edits; hashing unknown computed defaults causes churn.
func preservePortDefaults(_ context.Context, diff *schema.ResourceDiff, _ interface{}) error {
	config := diff.GetRawConfig()
	if config == cty.NilVal || config.IsNull() || !config.IsKnown() {
		return nil
	}
	ports := config.GetAttr("port_override")
	if ports.IsNull() || !ports.IsWhollyKnown() {
		return nil
	}
	old, planned := diff.GetChange("port_override")
	current := map[int]map[string]interface{}{}
	for _, value := range old.(*schema.Set).List() {
		port := value.(map[string]interface{})
		current[port["number"].(int)] = port
	}
	configured := map[int]cty.Value{}
	for iterator := ports.ElementIterator(); iterator.Next(); {
		_, value := iterator.Element()
		number, _ := value.GetAttr("number").AsBigFloat().Int64()
		if _, exists := configured[int(number)]; exists {
			return fmt.Errorf("duplicate port_override number %d", number)
		}
		configured[int(number)] = value
	}
	result := planned.(*schema.Set).List()
	for _, value := range result {
		port := value.(map[string]interface{})
		number := port["number"].(int)
		previous, exists := current[number]
		if !exists {
			continue
		}
		raw, exists := configured[number]
		if !exists {
			continue
		}
		for _, field := range computedPortFields {
			if raw.GetAttr(field).IsNull() {
				port[field] = previous[field]
			}
		}
	}
	return diff.SetNew("port_override", result)
}

var computedPortFields = []string{
	"native_networkconf_id", "tagged_vlan_mgmt", "forward",
	"excluded_network_ids", "voice_networkconf_id", "setting_preference",
}

// Configured empty sets clear exclusions; omitted computed sets preserve the
// controller snapshot even during first management, before state exists.
func configuredPortExclusions(config cty.Value) map[int]bool {
	result := map[int]bool{}
	if config == cty.NilVal || config.IsNull() || !config.IsKnown() {
		return result
	}
	ports := config.GetAttr("port_override")
	if ports.IsNull() || !ports.IsKnown() {
		return result
	}
	for iterator := ports.ElementIterator(); iterator.Next(); {
		_, port := iterator.Element()
		if port.IsNull() || !port.IsKnown() {
			continue
		}
		number := port.GetAttr("number")
		exclusions := port.GetAttr("excluded_network_ids")
		if !number.IsNull() && number.IsKnown() && !exclusions.IsNull() && exclusions.IsKnown() {
			index, _ := number.AsBigFloat().Int64()
			result[int(index)] = true
		}
	}
	return result
}
