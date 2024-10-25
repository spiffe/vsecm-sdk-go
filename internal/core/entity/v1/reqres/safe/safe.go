// VMware Secrets Manager (VSecM) Go SDK -- https://vsecm.com
// Copyright 2024-present VSecM SDK contributors.
// SPDX-License-Identifier: Apache-2.0
// Keep your secrets... secret.

package safe

import (
	"github.com/spiffe/vsecm-sdk-go/internal/core/constants/crypto"
	data2 "github.com/spiffe/vsecm-sdk-go/internal/core/entity/v1/data"
)

// SecretUpsertRequest is the request to upsert a secret.
type SecretUpsertRequest struct {
	WorkloadIds []string           `json:"workloads"`
	Namespaces  []string           `json:"namespaces"`
	Value       string             `json:"value"`
	Template    string             `json:"template"`
	Format      data2.SecretFormat `json:"format"`
	Encrypt     bool               `json:"encrypt"`
	NotBefore   string             `json:"notBefore"`
	Expires     string             `json:"expires"`

	Err string `json:"err,omitempty"`
}

// SecretUpsertResponse is the response to upsert a secret.
type SecretUpsertResponse struct {
	Err string `json:"err,omitempty"`
}

// KeyInputRequest is the request to provide new root encryption keys
// to VSecM Safe.
type KeyInputRequest struct {
	AgeSecretKey string `json:"ageSecretKey"`
	AgePublicKey string `json:"agePublicKey"`
	AesCipherKey string `json:"aesCipherKey"`
	Err          string `json:"err,omitempty"`
}

// SentinelInitCompleteRequest is the request to notify that VSecM Sentinel
// has completed initialization.
type SentinelInitCompleteRequest struct {
	Err string `json:"err,omitempty"`
}

// SentinelInitCompleteResponse is the response to SentinelInitCompleteRequest.
type SentinelInitCompleteResponse struct {
	Err string `json:"err,omitempty"`
}

// SecretFetchRequest is the request to fetch a secret.
type SecretFetchRequest struct {
	Err string `json:"err,omitempty"`
}

// SecretFetchResponse is the response to a SecretFetchRequest.
type SecretFetchResponse struct {
	Data    string `json:"data"`
	Created string `json:"created"`
	Updated string `json:"updated"`
	Err     string `json:"err,omitempty"`
}

type SecretStoreRequest struct {
	Key   string `json:"key"`
	Value string `json:"data"`
	Err   string `json:"err,omitempty"`
}

type SecretStoreResponse struct {
	Err string `json:"err,omitempty"`
}

// SecretDeleteRequest is the request to delete a secret.
type SecretDeleteRequest struct {
	WorkloadIds []string `json:"workloads"`
	Err         string   `json:"err,omitempty"`
}

// SecretDeleteResponse is the response to a SecretDeleteRequest.
type SecretDeleteResponse struct {
	Err string `json:"err,omitempty"`
}

// SecretListRequest is the request to list secrets.
// The response will not contain the secret values.
type SecretListRequest struct {
	Err string `json:"err,omitempty"`
}

// SecretListResponse is the response to a SecretListRequest.
type SecretListResponse struct {
	Secrets []data2.Secret `json:"secrets"`
	Err     string         `json:"err,omitempty"`
}

// SecretEncryptedListResponse is the response that lists secrets
// The secret values will be encrypted.
type SecretEncryptedListResponse struct {
	Secrets   []data2.SecretEncrypted `json:"secrets"`
	Algorithm crypto.Algorithm        `json:"algorithm"`
	Err       string                  `json:"err,omitempty"`
}

// KeystoneStatusRequest is the request to check the status of
// VSecM Keystone.
type KeystoneStatusRequest struct {
	Err string `json:"err,omitempty"`
}

// KeystoneStatusResponse is the response to a KeystoneStatusRequest.
type KeystoneStatusResponse struct {
	Status data2.InitStatus `json:"status"`
	Err    string           `json:"err,omitempty"`
}

// GenericRequest is the request for generic operations.
type GenericRequest struct {
	Err string `json:"err,omitempty"`
}

// GenericResponse is the response for generic operations.
type GenericResponse struct {
	Err string `json:"err,omitempty"`
}
