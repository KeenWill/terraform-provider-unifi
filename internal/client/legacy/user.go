package legacy

import (
	"context"
	"errors"
	"strings"

	"github.com/filipowm/go-unifi/unifi"
)

type UserLister interface {
	ListUser(context.Context, string) ([]unifi.User, error)
}

// ConfiguredUserByMAC selects configuration identity, never the observed client's
// ID. Site scoping is supplied by the collection endpoint; ambiguity is an error.
func ConfiguredUserByMAC(ctx context.Context, client UserLister, site, mac string) (*unifi.User, error) {
	users, err := client.ListUser(ctx, site)
	if err != nil {
		return nil, err
	}
	var found *unifi.User
	for _, user := range users {
		if !strings.EqualFold(user.MAC, mac) {
			continue
		}
		if found != nil {
			return nil, errors.New("multiple configured clients match MAC in this site")
		}
		if user.ID == "" {
			return nil, errors.New("configured client lacks an identity")
		}
		configured := user
		found = &configured
	}
	if found == nil {
		return nil, unifi.ErrNotFound
	}
	return found, nil
}
