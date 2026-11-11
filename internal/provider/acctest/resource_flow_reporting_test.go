package acctest

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"testing"

	"github.com/filipowm/terraform-provider-unifi/internal/client/integration"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/stretchr/testify/require"
)

func TestAccNetwork11FlowReporting(t *testing.T) {
	if os.Getenv("UNIFI_ACCTEST_LAB_FILE") == "" {
		t.Skip("requires disposable Network 11 lab")
	}
	ctx := context.Background()
	const root = "/proxy/network/v2/api/site/default/firewall-policies"
	var zones []struct {
		ID   string `json:"_id"`
		Name string `json:"name"`
	}
	require.NoError(t, testClient.Get(ctx, "/proxy/network/v2/api/site/default/firewall/zone", nil, &zones))
	ids := map[string]string{}
	for _, z := range zones {
		ids[z.Name] = z.ID
	}
	require.NotEmpty(t, ids["Internal"])
	require.NotEmpty(t, ids["External"])
	body := map[string]any{"name": "provider-acceptance-flow", "enabled": true, "action": "BLOCK", "ip_version": "BOTH", "protocol": "all", "source": map[string]string{"zone_id": ids["Internal"]}, "destination": map[string]string{"zone_id": ids["External"]}, "logging": false, "report_flow": false, "schedule": map[string]string{"mode": "ALWAYS"}, "create_allow_respond": false, "connection_state_type": "ALL"}
	var created struct {
		ID string `json:"_id"`
	}
	require.NoError(t, testClient.Post(ctx, root, body, &created))
	require.NotEmpty(t, created.ID)
	t.Cleanup(func() {
		if err := testClient.Delete(ctx, root+"/"+created.ID, nil, nil); err != nil {
			t.Errorf("delete lab policy: %v", err)
		}
	})
	c, err := integration.New(os.Getenv("UNIFI_API"), os.Getenv("UNIFI_API_KEY"), &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}})
	require.NoError(t, err)
	sites, err := c.Sites(ctx)
	require.NoError(t, err)
	site, err := integration.ResolveSite(sites, "default")
	require.NoError(t, err)
	policies, err := c.Policies(ctx, site)
	require.NoError(t, err)
	var id integration.ObjectID
	for _, p := range policies {
		if p.Name == "provider-acceptance-flow" {
			id = p.ID
		}
	}
	require.NotEmpty(t, id)
	before, err := c.FlowPolicy(ctx, site, id)
	require.NoError(t, err)
	delete(before.Document, "reportFlowEnabled")
	check := func(_ *terraform.State) error {
		after, err := c.FlowPolicy(ctx, site, id)
		if err != nil {
			return err
		}
		delete(after.Document, "reportFlowEnabled")
		if !reflect.DeepEqual(before.Document, after.Document) {
			return fmt.Errorf("unowned firewall policy fields changed")
		}
		return nil
	}
	config := func(enabled bool) string {
		return fmt.Sprintf("resource \"unifi_firewall_policy_flow_reporting\" \"test\" {\n site_id=%q\n policy_id=%q\n enabled=%t\n}\n", site, id, enabled)
	}
	AcceptanceTest(t, AcceptanceTestCase{VersionConstraint: "= 11.0.99", Steps: Steps{
		{Config: config(true), Check: resource.ComposeTestCheckFunc(resource.TestCheckResourceAttr("unifi_firewall_policy_flow_reporting.test", "enabled", "true"), check)},
		{ResourceName: "unifi_firewall_policy_flow_reporting.test", ImportState: true, ImportStateVerify: true},
		{Config: config(false), Check: resource.ComposeTestCheckFunc(resource.TestCheckResourceAttr("unifi_firewall_policy_flow_reporting.test", "enabled", "false"), check)},
	}})
}
