package site

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/filipowm/go-unifi/unifi"
	"github.com/stretchr/testify/require"

	"github.com/filipowm/terraform-provider-unifi/internal/provider/base"
)

type importSiteClient struct {
	unifi.Client
	lookupError error
	listError   error
	sites       []unifi.Site
	lookupID    string
	listCalled  bool
}

func (client *importSiteClient) GetSite(_ context.Context, id string) (*unifi.Site, error) {
	client.lookupID = id
	if client.lookupError != nil {
		return nil, client.lookupError
	}
	return &unifi.Site{ID: id}, nil
}

func (client *importSiteClient) ListSites(_ context.Context) ([]unifi.Site, error) {
	client.listCalled = true
	return client.sites, client.listError
}

func TestResourceSiteImport(t *testing.T) {
	denied := errors.New("unauthorized")
	for _, version := range []string{"10.6.109", "11.0.97"} {
		for _, test := range []struct {
			name          string
			importID      string
			lookupError   error
			listError     error
			expectedID    string
			expectedError string
			expectList    bool
		}{
			{name: "opaque ID", importID: "site-opaque-id", expectedID: "site-opaque-id"},
			{name: "short name", importID: "default", lookupError: fmt.Errorf("lookup: %w", unifi.ErrNotFound), expectedID: "site-opaque-id", expectList: true},
			{name: "unknown name", importID: "unknown", lookupError: unifi.ErrNotFound, expectedError: "unable to find site", expectList: true},
			{name: "lookup denied", importID: "default", lookupError: denied, expectedError: "unauthorized"},
			{name: "list denied", importID: "default", lookupError: unifi.ErrNotFound, listError: denied, expectedError: "unauthorized", expectList: true},
		} {
			t.Run(version+"/"+test.name, func(t *testing.T) {
				fake := &importSiteClient{lookupError: test.lookupError, listError: test.listError, sites: []unifi.Site{{ID: "site-opaque-id", Name: "default"}}}
				client := &base.Client{Client: fake, Version: base.AsVersion(version)}
				resource := ResourceSite()
				data := resource.TestResourceData()
				data.SetId(test.importID)
				result, err := resource.Importer.StateContext(context.Background(), data, client)
				require.Equal(t, test.importID, fake.lookupID)
				require.Equal(t, test.expectList, fake.listCalled)
				if test.expectedError != "" {
					require.ErrorContains(t, err, test.expectedError)
					require.Nil(t, result)
					require.Equal(t, test.importID, data.Id())
					return
				}
				require.NoError(t, err)
				require.Len(t, result, 1)
				require.Same(t, data, result[0])
				require.Equal(t, test.expectedID, result[0].Id())
			})
		}
	}
}

func TestResourceSiteReadMissingIdentity(t *testing.T) {
	for _, version := range []string{"10.6.109", "11.0.97"} {
		t.Run(version, func(t *testing.T) {
			fake := &importSiteClient{lookupError: unifi.ErrNotFound}
			client := &base.Client{Client: fake, Version: base.AsVersion(version)}
			resource := ResourceSite()
			data := resource.TestResourceData()
			data.SetId("managed-site-id")
			diagnostics := resource.ReadContext(context.Background(), data, client)
			if version == "11.0.97" {
				require.True(t, diagnostics.HasError())
				require.Contains(t, diagnostics[0].Summary, "identity reconciliation required")
				require.Equal(t, "managed-site-id", data.Id())
			} else {
				require.False(t, diagnostics.HasError())
				require.Empty(t, data.Id())
			}
			require.False(t, fake.listCalled)
		})
	}
}
