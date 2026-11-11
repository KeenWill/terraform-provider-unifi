package base

import (
	"context"
	"errors"
	"testing"

	"github.com/filipowm/go-unifi/unifi"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func TestMissingIdentityRequiresReconciliationOnNetwork11(t *testing.T) {
	for _, version := range []string{"10.6.106", "10.6.109", "11.0.89", "11.0.97", "11.0.99"} {
		t.Run(version, func(t *testing.T) {
			client := &Client{Version: AsVersion(version)}
			err := client.identityError(unifi.ErrNotFound, "WLAN", "default", "old-id")
			var migration *MissingIdentityError
			if version[:2] == "11" {
				if !errors.As(err, &migration) || errors.Is(err, unifi.ErrNotFound) {
					t.Fatalf("unsafe error %v", err)
				}
			} else if !errors.Is(err, unifi.ErrNotFound) {
				t.Fatal("changed older controller behavior")
			}
			denied := errors.New("unauthorized")
			if !errors.Is(client.identityError(denied, "WLAN", "default", "old-id"), denied) {
				t.Fatal("changed auth error")
			}
		})
	}
}

func TestLegacyImportPreservesOpaqueIDsAndRejectsUnsafeScope(t *testing.T) {
	for _, id := range []string{"0123456789abcdef01234567", "00000000-0000-4000-8000-000000000001", "future-opaque-id"} {
		resource := &schema.Resource{Schema: map[string]*schema.Schema{"site": {Type: schema.TypeString, Optional: true}}}
		data := schema.TestResourceDataRaw(t, resource.Schema, nil)
		data.SetId("default:" + id)
		_, err := ImportSiteAndID(context.Background(), data, nil)
		if err != nil || data.Id() != id || data.Get("site") != "default" {
			t.Fatalf("import %s: %v", id, err)
		}
	}
	for _, invalid := range []string{"", ":id", "default:", "default:id:extra", "../site:id", "default:../id", "default:%2f", "default:id?x=y"} {
		if _, _, err := parseLegacyImport(invalid, false); err == nil {
			t.Fatalf("accepted %q", invalid)
		}
	}
	if _, _, err := parseLegacyImport("id", true); err == nil {
		t.Fatal("accepted missing Framework site")
	}
}
