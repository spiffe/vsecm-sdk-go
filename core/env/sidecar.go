// VMware Secrets Manager (VSecM) Go SDK -- https://vsecm.com
// Copyright 2024-present VSecM SDK contributors.
// SPDX-License-Identifier: Apache-2.0
// Keep your secrets... secret.

package env

import (
	"github.com/spiffe/vsecm-sdk-go/core/constants/env"
)

// SecretsPathForSidecar returns the path to the secrets file used by the sidecar.
// The path is determined by the VSECM_SIDECAR_SECRETS_PATH environment variable,
// with a default value of "/opt/vsecm/secrets.json" if the variable is not set.
func SecretsPathForSidecar() string {
	p := env.Value(env.VSecMSidecarSecretsPath)
	if p == "" {
		p = string(env.VSecMSidecarSecretsPathDefault)
	}
	return p
}
