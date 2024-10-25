// VMware Secrets Manager (VSecM) Go SDK -- https://vsecm.com
// Copyright 2024-present VSecM SDK contributors.
// SPDX-License-Identifier: Apache-2.0
// Keep your secrets... secret.

package startup

import (
	"os"
	"time"

	"github.com/spiffe/vsecm-sdk-go/core/env"
	log "github.com/spiffe/vsecm-sdk-go/core/log/std"
	"github.com/spiffe/vsecm-sdk-go/lib/crypto"
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

	cid, _ := crypto.RandomString(8)
	if cid == "" {
		panic("Unable to create a secure correlation id.")
	}

	for {
		select {
		case <-ticker.C:
			log.InfoLn(&cid, "init:: tick")
			if initialized() {
				log.InfoLn(&cid, "initialized... exiting the init process")

				time.Sleep(waitTimeBeforeExit)

				os.Exit(0)
			}
		}
	}
}
