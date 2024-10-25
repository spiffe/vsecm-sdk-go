// VMware Secrets Manager (VSecM) Go SDK -- https://vsecm.com
// Copyright 2024-present VSecM SDK contributors.
// SPDX-License-Identifier: Apache-2.0
// Keep your secrets... secret.

package env

import (
	"strconv"
	"time"

	"github.com/spiffe/vsecm-sdk-go/core/constants/env"
)

// PollIntervalForSidecar returns the polling interval for sentry in time.Duration
// The interval is determined by the VSECM_SIDECAR_POLL_INTERVAL environment
// variable, with a default value of 20000 milliseconds if the variable is not
// set or if there is an error in parsing the value.
func PollIntervalForSidecar() time.Duration {
	p := env.Value(env.VSecMSidecarPollInterval)
	d, _ := strconv.Atoi(string(env.VSecMSidecarPollIntervalDefault))
	if p == "" {
		p = string(env.VSecMSidecarPollIntervalDefault)
	}

	i, err := strconv.ParseInt(p, 10, 32)
	if err != nil {
		i = int64(d)
		return time.Duration(i) * time.Millisecond
	}

	return time.Duration(i) * time.Millisecond
}
