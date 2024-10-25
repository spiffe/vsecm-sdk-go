// VMware Secrets Manager (VSecM) Go SDK -- https://vsecm.com
// Copyright 2024-present VSecM SDK contributors.
// SPDX-License-Identifier: Apache-2.0
// Keep your secrets... secret.

package env

import (
	"github.com/spiffe/vsecm-sdk-go/core/constants/env"
)

// EndpointUrlForSafe returns the URL for the VSecM Safe endpoint
// used in the VMware Secrets Manager system.
// The URL is obtained from the environment variable VSECM_SAFE_ENDPOINT_URL.
// If the variable is not set, the default URL is used.
func EndpointUrlForSafe() string {
	u := env.Value(env.VSecMSafeEndpointUrl)
	if u == "" {
		u = string(env.VSecMSafeEndpointUrlDefault)
	}
	return u
}
