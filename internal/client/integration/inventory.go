package integration

import (
	"context"
	"errors"
)

// API IDs and legacy site names are separate namespaces, even if text matches.
type (
	SiteID         string
	ObjectID       string
	LegacySiteName string
)

type ApplicationInfo struct {
	ApplicationVersion string `json:"applicationVersion"`
}
type Site struct {
	ID                SiteID         `json:"id"`
	InternalReference LegacySiteName `json:"internalReference"`
	Name              string         `json:"name"`
}

// DeviceDetails intentionally contains configuration inventory, not telemetry.
// Missing statistics after an upgrade cannot imply a missing device.
type DeviceDetails struct {
	ID         ObjectID `json:"id"`
	Name       string   `json:"name"`
	MACAddress string   `json:"macAddress"`
	IPAddress  string   `json:"ipAddress"`
	Model      string   `json:"model"`
	Interfaces struct {
		Radios []Radio `json:"radios"`
	} `json:"interfaces"`
}
type Radio struct {
	FrequencyGHz    float64 `json:"frequencyGHz"`
	Channel         *int    `json:"channel"`
	ChannelWidthMHz int     `json:"channelWidthMHz"`
	WLANStandard    string  `json:"wlanStandard"`
	// Nil means absent on older controllers; false/empty must not be invented.
	TXPowerMode *string `json:"txPowerMode"`
}

// PolicyOverview is a read model. It deliberately cannot represent a full PUT.
type PolicyOverview struct {
	ID                    ObjectID `json:"id"`
	Name                  string   `json:"name"`
	Description           *string  `json:"description"`
	Enabled               bool     `json:"enabled"`
	LoggingEnabled        bool     `json:"loggingEnabled"`
	ReportFlowEnabled     *bool    `json:"reportFlowEnabled"`
	ConnectionStateFilter []string `json:"connectionStateFilter"`
}

func (c *Client) Info(ctx context.Context) (*ApplicationInfo, error) {
	var info ApplicationInfo
	if err := c.get(ctx, "/info", nil, &info); err != nil {
		return nil, err
	}
	if info.ApplicationVersion == "" {
		return nil, errors.New("integration API info lacks application version")
	}
	return &info, nil
}

func (c *Client) Sites(ctx context.Context) ([]Site, error) {
	sites, err := list[Site](ctx, c, "/sites")
	if err != nil {
		return nil, err
	}
	seen := map[SiteID]bool{}
	for _, site := range sites {
		if segment(string(site.ID)) != nil || segment(string(site.InternalReference)) != nil || seen[site.ID] {
			return nil, errors.New("invalid or duplicate Integration API site identity")
		}
		seen[site.ID] = true
	}
	return sites, nil
}

// ResolveSite uses the documented internalReference, never a display-name guess.
func ResolveSite(sites []Site, legacyName LegacySiteName) (SiteID, error) {
	var matches []SiteID
	for _, site := range sites {
		if site.InternalReference == legacyName {
			matches = append(matches, site.ID)
		}
	}
	if len(matches) != 1 {
		return "", errors.New("legacy site does not map to exactly one Integration API site")
	}
	return matches[0], nil
}

func (c *Client) Device(ctx context.Context, site SiteID, id ObjectID) (*DeviceDetails, error) {
	if err := segment(string(site)); err != nil {
		return nil, err
	}
	if err := segment(string(id)); err != nil {
		return nil, err
	}
	var device DeviceDetails
	if err := c.get(ctx, "/sites/"+string(site)+"/devices/"+string(id), nil, &device); err != nil {
		return nil, err
	}
	if device.ID != id || device.MACAddress == "" {
		return nil, errors.New("integration API device identity mismatch")
	}
	return &device, nil
}

func (c *Client) Policies(ctx context.Context, site SiteID) ([]PolicyOverview, error) {
	if err := segment(string(site)); err != nil {
		return nil, err
	}
	policies, err := list[PolicyOverview](ctx, c, "/sites/"+string(site)+"/firewall/policies")
	if err != nil {
		return nil, err
	}
	seen := map[ObjectID]bool{}
	for _, policy := range policies {
		if segment(string(policy.ID)) != nil || seen[policy.ID] {
			return nil, errors.New("invalid or duplicate Integration API policy identity")
		}
		seen[policy.ID] = true
	}
	return policies, nil
}
