// VMware Secrets Manager (VSecM) Go SDK -- https://vsecm.com
// Copyright 2024-present VSecM SDK contributors.
// SPDX-License-Identifier: Apache-2.0
// Keep your secrets... secret.

package startup

import (
	"github.com/spiffe/vsecm-sdk-go/internal/debug"
	"os"
	"time"

	"github.com/spiffe/vsecm-sdk-go/internal/core/env"
)

// Watch continuously polls the associated secret of the workload to exist.
// If the secret exists, and it is not empty, the function exits the init
// container with a success status code (0).
//
//   - waitTimeBeforeExit: The duration to wait before a successful exit from
//     the function.
func Watch(waitTimeBeforeExit time.Duration) {
	interval := env.PollIntervalForInitContainer()
	ticker := time.NewTicker(interval)

	for {
		select {
		case <-ticker.C:
			debug.Log("init:: tick")
			if initialized() {
				debug.Log("initialized... exiting the init process")

				time.Sleep(waitTimeBeforeExit)

				os.Exit(0)
			}
		}
	}
}
