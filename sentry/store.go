// VMware Secrets Manager (VSecM) Go SDK -- https://vsecm.com
// Copyright 2024-present VSecM SDK contributors.
// SPDX-License-Identifier: Apache-2.0
// Keep your secrets... secret.

package sentry

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"golang.org/x/net/context"

	"github.com/spiffe/vsecm-sdk-go/internal/config"
	reqres "github.com/spiffe/vsecm-sdk-go/internal/core/entity/v1/reqres/safe"
	"github.com/spiffe/vsecm-sdk-go/internal/core/env"
	"github.com/spiffe/vsecm-sdk-go/internal/core/validation"
	"github.com/spiffe/vsecm-sdk-go/internal/debug"
)

// Store securely saves a secret value associated with a key in the VSecM Safe
// storage.
//
// Store establishes a secure connection to the VSecM Safe API endpoint using
// SPIFFE-based mTLS authentication. It validates that the calling workload has
// appropriate permissions to store secrets by checking its SPIFFE ID against
// known trusted identities.
//
// The method automatically prepends "raw:" to the provided key before storage.
// This is part of VSecM's key namespace management: The "raw:" prefix indicates
// that the secret will not be associated with any workload and an orchestrator
// or an operator such as VSecM Scout will need to fetch and distribute it.
//
// Parameters:
//   - key: The identifier for the secret. Will be prefixed with "raw:"
//     internally.
//   - value: The secret value to store.
//
// Returns:
//   - reqres.SecretStoreResponse: Contains the server's response after
//     storing the secret.
//   - error: Returns nil on success. Possible errors include:
//   - SPIFFE Workload API connection failures
//   - Authentication/authorization failures
//   - Network connectivity issues
//   - Invalid workload identity
//   - API endpoint communication errors
//
// The method implements several security best practices:
//   - Uses short-lived mTLS connections with SPIFFE-based authentication
//   - Validates workload identity before allowing secret storage
//   - Implements connection pooling optimizations
//   - Properly closes all resources to prevent leaks
//
// Example:
//
//	resp, err := Store("database-password", "secret123")
//	if err != nil {
//	    log.Fatalf("Failed to store secret: %v", err)
//	}
//
// Note: This method is only available to workloads with clerk privileges in the
// VSecM security model. Attempting to store secrets from unauthorized workloads
// will result in an error.
func Store(key, value string) (reqres.SecretStoreResponse, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var source *workloadapi.X509Source
	source, err := workloadapi.NewX509Source(
		ctx, workloadapi.WithClientOptions(
			workloadapi.WithAddr(env.SpiffeSocketUrl()),
		),
	)
	if err != nil {
		return reqres.SecretStoreResponse{},
			errors.Join(
				err,
				errors.New(
					"store: failed getting SVID Bundle from the SPIFFE Workload API",
				),
			)
	}

	defer func(s *workloadapi.X509Source) {
		if s == nil {
			return
		}
		err := s.Close()
		if err != nil {
			if config.SdkConfig.Debug {
				debug.Log("store: problem closing source: ", err.Error())
			}
		}
	}(source)

	svid, err := source.GetX509SVID()
	if err != nil {
		return reqres.SecretStoreResponse{},
			errors.Join(
				err,
				errors.New("store: error getting SVID from source"),
			)
	}

	// Make sure that we are calling Safe from a workload that can write
	// raw secrets.
	if !validation.IsClerk(svid.ID.String()) {
		return reqres.SecretStoreResponse{},
			errors.New("store: untrusted workload: '" + svid.ID.String() + "'")
	}

	authorizer := tlsconfig.AdaptMatcher(func(id spiffeid.ID) error {
		if validation.IsSafe(id.String()) {
			return nil
		}

		return errors.New("store: I don't know you, and it's crazy: '" +
			id.String() + "'")
	})

	p, err := url.JoinPath(env.EndpointUrlForSafe(), "/workload/v1/secrets")
	if err != nil {
		return reqres.SecretStoreResponse{},
			errors.New("fetch: problem generating server url")
	}

	client := &http.Client{
		Transport: &http.Transport{
			// Use the connection to serve a single http request only.
			// This is not a web server; there is no need to keep the
			// connection open for multiple requests. This will also
			// save a good chunk of memory, especially when polling
			// interval is shorter. [1]
			DisableKeepAlives: true,
			TLSClientConfig:   tlsconfig.MTLSClientConfig(source, source, authorizer),
		},
	}

	debug.Log("Sentry:Store", p)
	debug.Log("Sentry:Store svid:id: ", svid.ID.String())

	sr := &reqres.SecretStoreRequest{
		Key:   "raw:" + key,
		Value: value,
	}

	md, err := json.Marshal(sr)
	if err != nil {
		return reqres.SecretStoreResponse{}, errors.Join(
			err,
			errors.New("store: I am having problem generating the payload"),
		)
	}

	r, err := client.Post(p, "application/json", bytes.NewBuffer(md))

	if err != nil {
		return reqres.SecretStoreResponse{}, errors.Join(
			err,
			errors.New("store: Problem connecting to VSecM Safe API endpoint URL"),
		)
	}

	if r.StatusCode != http.StatusOK {
		return reqres.SecretStoreResponse{},
			errors.New("store: Problem connecting to VSecM Safe API endpoint URL")
	}

	defer func(b io.ReadCloser) {
		err := b.Close()
		if err != nil {
			if err != nil {
				debug.Log("Fetch: problem closing response body: ", err.Error())
			}
		}
	}(r.Body)

	// Hint the server that we wish to close the connection
	// as soon as we are done with it.
	r.Close = true

	if r.StatusCode == http.StatusNotFound {
		return reqres.SecretStoreResponse{}, ErrSecretNotFound
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return reqres.SecretStoreResponse{}, errors.Join(
			err,
			errors.New(
				"unable to read the response body from VSecM Safe API endpoint",
			),
		)
	}

	var ssr reqres.SecretStoreResponse
	err = json.Unmarshal(body, &ssr)
	if err != nil {
		return reqres.SecretStoreResponse{}, errors.Join(
			err,
			errors.New("unable to deserialize response"),
		)
	}

	return ssr, nil
}
