// VMware Secrets Manager (VSecM) Go SDK -- https://vsecm.com
// Copyright 2024-present VSecM SDK contributors.
// SPDX-License-Identifier: Apache-2.0
// Keep your secrets... secret.

package sentry

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"github.com/spiffe/vsecm-sdk-go/internal/config"
	reqres "github.com/spiffe/vsecm-sdk-go/internal/core/entity/v1/reqres/safe"
	env2 "github.com/spiffe/vsecm-sdk-go/internal/core/env"
	"github.com/spiffe/vsecm-sdk-go/internal/core/validation"
	"github.com/spiffe/vsecm-sdk-go/internal/debug"
)

// ErrSecretNotFound is returned when the secret is not found.
var ErrSecretNotFound = errors.New("secret does not exist")

// Fetch fetches the up-to-date secret that has been registered to the workload.
//
//	secret, err := sentry.Fetch()
//
// In case of a problem, Fetch will return an empty string and an error explaining
// what went wrong.
//
// Fetch can ONLY be called from a registered workload; and it ONLY delivers
// the secret that the workload is associated with.
func Fetch() (reqres.SecretFetchResponse, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var source *workloadapi.X509Source
	source, err := workloadapi.NewX509Source(
		ctx, workloadapi.WithClientOptions(
			workloadapi.WithAddr(env2.SpiffeSocketUrl()),
		),
	)
	if err != nil {
		return reqres.SecretFetchResponse{},
			errors.Join(
				err,
				errors.New(
					"fetch: failed getting SVID Bundle from the SPIFFE Workload API",
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
				debug.Log("Fetch: problem closing source: ", err.Error())
			}
		}
	}(source)

	svid, err := source.GetX509SVID()
	if err != nil {
		return reqres.SecretFetchResponse{},
			errors.Join(
				err,
				errors.New("fetch: error getting SVID from source"),
			)
	}

	// Make sure that we are calling Safe from a workload that VSecM knows about.
	if !validation.IsWorkload(svid.ID.String()) {
		return reqres.SecretFetchResponse{},
			errors.New("fetch: untrusted workload: '" + svid.ID.String() + "'")
	}

	authorizer := tlsconfig.AdaptMatcher(func(id spiffeid.ID) error {
		if validation.IsSafe(id.String()) {
			return nil
		}

		return errors.New("Fetch: I don't know you, and it's crazy: '" + id.String() + "'")
	})

	p, err := url.JoinPath(env2.EndpointUrlForSafe(), "/workload/v1/secrets")
	if err != nil {
		return reqres.SecretFetchResponse{},
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

	debug.Log("Sentry:Fetch", p)
	debug.Log("Sentry:Fetch svid:id: ", svid.ID.String())

	r, err := client.Get(p)
	if err != nil {
		return reqres.SecretFetchResponse{}, errors.Join(
			err,
			errors.New("fetch: problem connecting to VSecM Safe API endpoint"),
		)
	}

	defer func(b io.ReadCloser) {
		err := b.Close()
		if err != nil {
			if err != nil {
				debug.Log("Fetch: problem closing response body: ", err.Error())
			}
		}
	}(r.Body)

	// Related to [1]. Hint the server that we wish to close the connection
	// as soon as we are done with it.
	r.Close = true

	if r.StatusCode == http.StatusNotFound {
		return reqres.SecretFetchResponse{}, ErrSecretNotFound
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return reqres.SecretFetchResponse{}, errors.Join(
			err,
			errors.New(
				"unable to read the response body from VSecM Safe API endpoint",
			),
		)
	}

	var sfr reqres.SecretFetchResponse
	err = json.Unmarshal(body, &sfr)
	if err != nil {
		return reqres.SecretFetchResponse{}, errors.Join(
			err,
			errors.New("unable to deserialize response"),
		)
	}

	return sfr, nil
}
