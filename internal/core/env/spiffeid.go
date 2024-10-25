// VMware Secrets Manager (VSecM) Go SDK -- https://vsecm.com
// Copyright 2024-present VSecM SDK contributors.
// SPDX-License-Identifier: Apache-2.0
// Keep your secrets... secret.

package env

import (
	"github.com/spiffe/vsecm-sdk-go/internal/core/constants/env"
)

// SpiffeIdPrefixForSafe returns the prefix for the Safe SPIFFE ID.
// The prefix is obtained from the environment variable
// VSECM_SPIFFEID_PREFIX_SAFE. If the variable is not set, the default prefix is
// used.
func SpiffeIdPrefixForSafe() string {
	p := env.Value(env.VSecMSpiffeIdPrefixSafe)
	if p == "" {
		p = string(env.VSecMSpiffeIdPrefixSafeDefault)
	}
	return p
}

func SpiffeIdPrefixForClerk() string {
	p := env.Value(env.VSecMSpiffeIdPrefixClerk)
	if p == "" {
		p = string(env.VSecMSpiffeIdPrefixClerkDefault)
	}
	return p
}

// SpiffeIdPrefixForWorkload returns the prefix for the Workload's SPIFFE ID.
// The prefix is obtained from the environment variable
// VSECM_SPIFFEID_PREFIX_WORKLOAD.
// If the variable is not set, the default prefix is used.
func SpiffeIdPrefixForWorkload() string {
	p := env.Value(env.VSecMSpiffeIdPrefixWorkload)
	if p == "" {
		p = string(env.VSecMSpiffeIdPrefixWorkloadDefault)
	}
	return p
}

// NameRegExpForWorkload returns the regular expression pattern for extracting
// the workload name from the SPIFFE ID.
// The prefix is obtained from the environment variable
// VSECM_NAME_REGEXP_FOR_WORKLOAD.
// If the variable is not set, the default pattern is used.
func NameRegExpForWorkload() string {
	p := env.Value(env.VSecMWorkloadNameRegExp)
	if p == "" {
		p = string(env.VSecMNameRegExpForWorkloadDefault)
	}
	return p
}
