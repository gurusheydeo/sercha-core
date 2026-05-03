package auth

import (
	"fmt"
	"net/url"
)

// BuildAdminConsentURL composes a consent-redirect URL from the supplied
// components. It is provider-agnostic: callers supply the consent endpoint
// and any extra query parameters specific to the provider
// (e.g. "prompt=admin_consent" for Microsoft, "approval_prompt=force" for
// Google Workspace). Standard OAuth parameters (client_id, redirect_uri,
// state) are always included.
//
// All parameter values are URL-encoded. An error is returned only when the
// consentEndpoint cannot be parsed as a URL.
func BuildAdminConsentURL(
	consentEndpoint, clientID, redirectURI, state string,
	extra map[string]string,
) (string, error) {
	base, err := url.Parse(consentEndpoint)
	if err != nil {
		return "", fmt.Errorf("parse consent endpoint: %w", err)
	}

	q := base.Query()
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)

	for k, v := range extra {
		q.Set(k, v)
	}

	base.RawQuery = q.Encode()
	return base.String(), nil
}
