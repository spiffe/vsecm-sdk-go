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

// PollIntervalForInitContainer returns the time interval between each poll in the
// Watch function. The interval is specified in milliseconds as the
// VSECM_INIT_CONTAINER_POLL_INTERVAL environment variable.  If the environment
// variable is not set or is not a valid integer value, the function returns the
// default interval of 5000 milliseconds.
func PollIntervalForInitContainer() time.Duration {
	p := env.Value(env.VSecMInitContainerPollInterval)
	d, _ := strconv.Atoi(string(env.VSecMInitContainerPollIntervalDefault))
	if p == "" {
		p = string(env.VSecMInitContainerPollIntervalDefault)
	}

	i, err := strconv.ParseInt(p, 10, 32)
	if err != nil {
		i = int64(d)
		return time.Duration(i) * time.Millisecond
	}

	return time.Duration(i) * time.Millisecond
}
