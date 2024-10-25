// VMware Secrets Manager (VSecM) Go SDK -- https://vsecm.com
// Copyright 2024-present VSecM SDK contributors.
// SPDX-License-Identifier: Apache-2.0
// Keep your secrets... secret.

package sentry

import (
	"time"

	"github.com/spiffe/vsecm-sdk-go/core/env"
	log "github.com/spiffe/vsecm-sdk-go/core/log/std"
	"github.com/spiffe/vsecm-sdk-go/lib/backoff"
	"github.com/spiffe/vsecm-sdk-go/lib/crypto"
)

// Watch synchronizes the internal state of the sidecar by talking to
// VSecM Safe regularly. It periodically calls Fetch behind-the-scenes to
// get its work done. Once it fetches the secrets, it saves it to
// the location defined in the `VSECM_SIDECAR_SECRETS_PATH` environment
// variable (`/opt/vsecm/secrets.json` by default).
func Watch() {
	interval := env.PollIntervalForSidecar()

	cid, _ := crypto.RandomString(8)
	if cid == "" {
		panic("Unable to create a secure correlation id.")
	}

	for {
		_ = backoff.Retry("sentry.Watch", func() error {
			err := fetchSecrets()
			if err != nil {
				log.InfoLn(&cid, "Could not fetch secrets", err.Error(),
					". Will retry in", interval, ".")
			}
			return err
		}, backoff.Strategy{
			MaxRetries:  10,
			Delay:       interval,
			Exponential: false,
		})

		time.Sleep(interval)
	}
}
