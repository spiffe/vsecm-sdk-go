// VMware Secrets Manager (VSecM) Go SDK -- https://vsecm.com
// Copyright 2024-present VSecM SDK contributors.
// SPDX-License-Identifier: Apache-2.0
// Keep your secrets... secret.

package env

import (
	"github.com/spiffe/vsecm-sdk-go/internal/core/constants/env"
)

// SpiffeSocketUrl returns the URL for the SPIFFE endpoint socket used in the
// VMware Secrets Manager system. The URL is obtained from the environment variable
// SPIFFE_ENDPOINT_SOCKET. If the variable is not set, the default URL is used.
func SpiffeSocketUrl() string {
	p := env.Value(env.SpiffeEndpointSocket)
	if p == "" {
		p = string(env.SpiffeEndpointSocketDefault)
	}
	return p
}

// SpiffeTrustDomain retrieves the SPIFFE trust domain from environment
// variables.
//
// This function looks for the trust domain using the environment variable
// defined by `constants.SpiffeTrustDomain`. If the environment variable is not
// set or is an empty string, it defaults to the value specified by
// `constants.SpiffeTrustDomainDefault`.
//
// Returns:
//   - A string representing the SPIFFE trust domain.
func SpiffeTrustDomain() string {
	p := env.Value(env.SpiffeTrustDomain)
	if p == "" {
		p = string(env.SpiffeTrustDomainDefault)
	}
	return p
}
