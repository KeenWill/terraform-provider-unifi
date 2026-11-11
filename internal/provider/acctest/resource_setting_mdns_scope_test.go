package acctest

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/filipowm/terraform-provider-unifi/internal/client/legacy"
	pt "github.com/filipowm/terraform-provider-unifi/internal/provider/testing"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/stretchr/testify/require"
)

func TestAccNetwork11MDNSScope(t *testing.T) {
	if os.Getenv("UNIFI_ACCTEST_LAB_FILE") == "" {
		t.Skip("requires the disposable Network 11 lab")
	}
	original, err := legacy.ReadMDNSScope(context.Background(), testClient, "default")
	require.NoError(t, err)
	const globalPath = "/proxy/network/v2/api/site/default/global/config/network"
	var unowned map[string]interface{}
	require.NoError(t, testClient.Get(context.Background(), globalPath, nil, &unowned))
	delete(unowned, "mdns_enabled_for")
	delete(unowned, "mdns_enabled_for_network_ids")
	checkUnowned := func(_ *terraform.State) error {
		var actual map[string]interface{}
		if err := testClient.Get(context.Background(), globalPath, nil, &actual); err != nil {
			return err
		}
		delete(actual, "mdns_enabled_for")
		delete(actual, "mdns_enabled_for_network_ids")
		if !reflect.DeepEqual(unowned, actual) {
			return fmt.Errorf("an unowned global network setting changed")
		}
		return nil
	}
	t.Cleanup(func() {
		_, err := legacy.UpdateMDNSScope(context.Background(), testClient, "default", original)
		if err != nil {
			t.Errorf("restore lab mDNS scope: %v", err)
		}
	})
	networks, err := testClient.ListNetwork(context.Background(), "default")
	require.NoError(t, err)
	require.NotEmpty(t, networks)
	config := func(scope string) string {
		networkIDs := ""
		if scope == "some" {
			networkIDs = fmt.Sprintf("network_ids = [%q]", networks[0].ID)
		}
		return fmt.Sprintf("resource \"unifi_setting_mdns_scope\" \"test\" {\n scope = %q\n %s\n}\n", scope, networkIDs)
	}
	AcceptanceTest(t, AcceptanceTestCase{VersionConstraint: "= 11.0.99", Steps: Steps{
		{Config: config("none"), Check: resource.ComposeTestCheckFunc(resource.TestCheckResourceAttr("unifi_setting_mdns_scope.test", "scope", "none"), checkUnowned)},
		pt.ImportStepWithSite("unifi_setting_mdns_scope.test"),
		{Config: config("some"), Check: resource.ComposeTestCheckFunc(resource.TestCheckResourceAttr("unifi_setting_mdns_scope.test", "scope", "some"), resource.TestCheckResourceAttr("unifi_setting_mdns_scope.test", "network_ids.#", "1"), checkUnowned)},
		{Config: config("all"), Check: resource.ComposeTestCheckFunc(resource.TestCheckResourceAttr("unifi_setting_mdns_scope.test", "scope", "all"), checkUnowned)},
	}})
}
