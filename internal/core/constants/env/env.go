// VMware Secrets Manager (VSecM) Go SDK -- https://vsecm.com
// Copyright 2024-present VSecM SDK contributors.
// SPDX-License-Identifier: Apache-2.0
// Keep your secrets... secret.

package env

import (
	"os"
)

type VarName string

const SpiffeEndpointSocket VarName = "SPIFFE_ENDPOINT_SOCKET"
const SpiffeTrustDomain VarName = "SPIFFE_TRUST_DOMAIN"
const VSecMInitContainerPollInterval VarName = "VSECM_INIT_CONTAINER_POLL_INTERVAL"
const VSecMLogLevel VarName = "VSECM_LOG_LEVEL"
const VSecMSafeEndpointUrl VarName = "VSECM_SAFE_ENDPOINT_URL"
const VSecMSidecarPollInterval VarName = "VSECM_SIDECAR_POLL_INTERVAL"
const VSecMSidecarSecretsPath VarName = "VSECM_SIDECAR_SECRETS_PATH"
const VSecMSpiffeIdPrefixSafe VarName = "VSECM_SPIFFEID_PREFIX_SAFE"
const VSecMSpiffeIdPrefixClerk VarName = "VSECM_SPIFFEID_PREFIX_SAFE"
const VSecMSpiffeIdPrefixWorkload VarName = "VSECM_SPIFFEID_PREFIX_WORKLOAD"
const VSecMWorkloadNameRegExp VarName = "VSECM_WORKLOAD_NAME_REGEXP"

type VarValue string

const SpiffeEndpointSocketDefault VarValue = "unix:///spire-agent-socket/spire-agent.sock"
const SpiffeTrustDomainDefault VarValue = "vsecm.com"
const VSecMInitContainerPollIntervalDefault VarValue = "5000"
const VSecMSafeEndpointUrlDefault VarValue = "https://vsecm-safe.vsecm-system.svc.cluster.local:8443/"
const VSecMSidecarPollIntervalDefault VarValue = "20000"
const VSecMSidecarSecretsPathDefault VarValue = "/opt/vsecm/secrets.json"
const VSecMSpiffeIdPrefixSafeDefault VarValue = "^spiffe://vsecm.com/workload/vsecm-safe/ns/vsecm-system/sa/vsecm-safe/n/[^/]+$"
const VSecMSpiffeIdPrefixClerkDefault VarValue = "^spiffe://vsecm.com/workload/vsecm-clerk/ns/vsecm-clerk/sa/vsecm-safe/n/[^/]+$"
const VSecMSpiffeIdPrefixWorkloadDefault VarValue = "^spiffe://vsecm.com/workload/[^/]+/ns/[^/]+/sa/[^/]+/n/[^/]+$"
const VSecMNameRegExpForWorkloadDefault VarValue = "^spiffe://vsecm.com/workload/([^/]+)/ns/[^/]+/sa/[^/]+/n/[^/]+$"

func Value(name VarName) string {
	return os.Getenv(string(name))
}

type FieldName string
