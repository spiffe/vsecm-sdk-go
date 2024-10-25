// VMware Secrets Manager (VSecM) Go SDK -- https://vsecm.com
// Copyright 2024-present VSecM SDK contributors.
// SPDX-License-Identifier: Apache-2.0
// Keep your secrets... secret.

package crypto

import (
	"fmt"

	"github.com/spiffe/vsecm-sdk-go/lib/crypto"
)

// Id generates a cryptographically-unique secure random string.
func Id() string {
	id, err := crypto.RandomString(8)
	if err != nil {
		id = fmt.Sprintf("CRYPTO-ERR: %s", err.Error())
	}
	return id
}
