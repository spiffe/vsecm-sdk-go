// VMware Secrets Manager (VSecM) Go SDK -- https://vsecm.com
// Copyright 2024-present VSecM SDK contributors.
// SPDX-License-Identifier: Apache-2.0
// Keep your secrets... secret.

package data

import "github.com/spiffe/vsecm-sdk-go/lib/entity"

// SecretFormat represents the format of the secret.
type SecretFormat string

var (
	Json SecretFormat = "json"
	Yaml SecretFormat = "yaml"
	Raw  SecretFormat = "raw"
)

// Secret represents the secret that is safe to view.
type Secret struct {
	Name         string          `json:"name"`
	Created      entity.JsonTime `json:"created"`
	Updated      entity.JsonTime `json:"updated"`
	NotBefore    entity.JsonTime `json:"notBefore"`
	ExpiresAfter entity.JsonTime `json:"expiresAfter"`
}

// SecretEncrypted represents the secret with an encrypted value.
// It is still safe to view since the value of it is encrypted.
type SecretEncrypted struct {
	Name           string          `json:"name"`
	EncryptedValue string          `json:"value"`
	Created        entity.JsonTime `json:"created"`
	Updated        entity.JsonTime `json:"updated"`
	NotBefore      entity.JsonTime `json:"notBefore"`
	ExpiresAfter   entity.JsonTime `json:"expiresAfter"`
}

// SecretMeta represents the metadata of the secret that is not
// directly relevant to the secret itself but provides additional
// context for VSecM Safe's internal operations.
type SecretMeta struct {
	// Defaults to "default"
	Namespaces []string `json:"namespaces"`
	// Go template used to transform the secret.
	// Sample secret:
	// '{"username":"admin","password":"VSecMRocks"}'
	// Sample template:
	// '{"USER":"{{.username}}", "PASS":"{{.password}}"}"
	Template string `json:"template"`
	// Defaults to None
	Format SecretFormat
	// For tracking purposes
	CorrelationId string `json:"correlationId"`
}
