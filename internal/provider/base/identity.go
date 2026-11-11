package base

import (
	"context"
	"errors"
	"fmt"

	"github.com/filipowm/go-unifi/unifi"
)

// MissingIdentityError intentionally does not unwrap to ErrNotFound: the SDK
// resource handlers must retain state instead of planning duplicate creation.
type MissingIdentityError struct{ Kind, Site, ID string }

func (err *MissingIdentityError) Error() string {
	return fmt.Sprintf("Network 11 identity reconciliation required: %s %q in site %q is missing; preserve state, compare a scoped identity inventory, and review explicit imports before any mutation", err.Kind, err.ID, err.Site)
}

func (c *Client) identityError(err error, kind, site, id string) error {
	if errors.Is(err, unifi.ErrNotFound) && c.Version != nil && c.Version.Segments()[0] >= 11 {
		return &MissingIdentityError{Kind: kind, Site: site, ID: id}
	}
	return err
}

func (c *Client) GetUser(ctx context.Context, site, id string) (*unifi.User, error) {
	result, err := c.Client.GetUser(ctx, site, id)
	return result, c.identityError(err, "configured client", site, id)
}

func (c *Client) GetNetwork(ctx context.Context, site, id string) (*unifi.Network, error) {
	result, err := c.Client.GetNetwork(ctx, site, id)
	return result, c.identityError(err, "Network", site, id)
}

func (c *Client) GetWLAN(ctx context.Context, site, id string) (*unifi.WLAN, error) {
	result, err := c.Client.GetWLAN(ctx, site, id)
	return result, c.identityError(err, "WLAN", site, id)
}

func (c *Client) GetDevice(ctx context.Context, site, id string) (*unifi.Device, error) {
	result, err := c.Client.GetDevice(ctx, site, id)
	return result, c.identityError(err, "Device", site, id)
}

func (c *Client) GetPortProfile(ctx context.Context, site, id string) (*unifi.PortProfile, error) {
	result, err := c.Client.GetPortProfile(ctx, site, id)
	return result, c.identityError(err, "PortProfile", site, id)
}

func (c *Client) GetUserGroup(ctx context.Context, site, id string) (*unifi.UserGroup, error) {
	result, err := c.Client.GetUserGroup(ctx, site, id)
	return result, c.identityError(err, "UserGroup", site, id)
}

func (c *Client) GetSite(ctx context.Context, id string) (*unifi.Site, error) {
	result, err := c.Client.GetSite(ctx, id)
	return result, c.identityError(err, "site", "", id)
}

func (c *Client) GetRouting(ctx context.Context, site, id string) (*unifi.Routing, error) {
	result, err := c.Client.GetRouting(ctx, site, id)
	return result, c.identityError(err, "Routing", site, id)
}

func (c *Client) GetFirewallGroup(ctx context.Context, site, id string) (*unifi.FirewallGroup, error) {
	result, err := c.Client.GetFirewallGroup(ctx, site, id)
	return result, c.identityError(err, "FirewallGroup", site, id)
}

func (c *Client) GetFirewallRule(ctx context.Context, site, id string) (*unifi.FirewallRule, error) {
	result, err := c.Client.GetFirewallRule(ctx, site, id)
	return result, c.identityError(err, "FirewallRule", site, id)
}
