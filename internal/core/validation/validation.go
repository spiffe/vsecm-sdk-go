// VMware Secrets Manager (VSecM) Go SDK -- https://vsecm.com
// Copyright 2024-present VSecM SDK contributors.
// SPDX-License-Identifier: Apache-2.0
// Keep your secrets... secret.

package validation

import (
	e "github.com/spiffe/vsecm-sdk-go/internal/core/constants/env"
	env2 "github.com/spiffe/vsecm-sdk-go/internal/core/env"
	"regexp"
	"strings"
)

// Any SPIFFE ID regular expression matcher shall start with the
// `^spiffe://$trustDomain` prefix for extra security.
//
// This variable shall be treated as constant and should not be modified.
var spiffeRegexPrefixStart = "^spiffe://" + env2.SpiffeTrustDomain() + "/"
var spiffeIdPrefixStart = "spiffe://" + env2.SpiffeTrustDomain() + "/"

// IsWorkload checks if a given SPIFFE ID belongs to a workload.
//
// A SPIFFE ID (SPIFFE IDentifier) is a URI that uniquely identifies a workload
// in a secure, interoperable way. This function verifies if the provided
// SPIFFE ID meets the criteria to be classified as a workload ID based on
// certain environmental settings.
//
// The function performs the following checks:
//  1. If the `spiffeid` starts with a "^", it assumed that it is a regular
//     expression pattern, it compiles the expression and checks if the SPIFFE
//     ID matches it.
//  2. Otherwise, it checks if the SPIFFE ID starts with the proper prefix.
//
// Parameters:
//
//	spiffeid (string): The SPIFFE ID to be checked.
//
// Returns:
//
//	bool: `true` if the SPIFFE ID belongs to a workload, `false` otherwise.
func IsWorkload(spiffeid string) bool {

	// "spiffe://mephisto.vsecm.com/workload/mephisto-edge-store/ns/default/sa/default/n/edge-store-7b9468d7cf-675b7"
	// prefix: "^spiffe://mephisto.vsecm.com/workload/[^/]+/ns/[^/]+/sa/[^/]+/n/[^/]+$"
	// workload regex: ^spiffe://mephisto.vsecm.com/workload/([^/]+)/ns/[^/]+/sa/[^/]+/n/[^/]+$
	prefix := env2.SpiffeIdPrefixForWorkload()

	if strings.HasPrefix(prefix, spiffeRegexPrefixStart) {
		re, err := regexp.Compile(prefix)
		if err != nil {
			panic(
				"Failed to compile the regular expression pattern " +
					"for SPIFFE ID." +
					" Check the " + string(e.VSecMSpiffeIdPrefixWorkload) +
					" environment variable. " +
					" val: " + env2.SpiffeIdPrefixForWorkload() +
					" trust: " + env2.SpiffeTrustDomain(),
			)
			return false
		}

		nrw := env2.NameRegExpForWorkload()
		wre, err := regexp.Compile(nrw)
		if err != nil {
			panic(
				"Failed to compile the regular expression pattern " +
					"for SPIFFE ID." +
					" Check the " + string(e.VSecMWorkloadNameRegExp) +
					" environment variable." +
					" val: " + env2.NameRegExpForWorkload() +
					" trust: " + env2.SpiffeTrustDomain(),
			)
			return false
		}

		match := wre.FindStringSubmatch(spiffeid)
		if len(match) == 0 {
			return false
		}

		return re.MatchString(spiffeid)
	}

	if !strings.HasPrefix(spiffeid, spiffeIdPrefixStart) {
		return false
	}

	nrw := env2.NameRegExpForWorkload()
	if !strings.HasPrefix(nrw, spiffeRegexPrefixStart) {

		// Insecure configuration detected.
		// Panic to prevent further issues:
		panic(
			"Invalid regular expression pattern for SPIFFE ID." +
				" Expected: ^spiffe://<trust_domain>/..." +
				" Check the " + string(e.VSecMWorkloadNameRegExp) +
				" environment variable." +
				" val: " + env2.NameRegExpForWorkload() +
				" trust: " + env2.SpiffeTrustDomain(),
		)
		return false
	}

	wre, err := regexp.Compile(nrw)
	if err != nil {
		panic(
			"Failed to compile the regular expression pattern " +
				"for SPIFFE ID." +
				" Check the " + string(e.VSecMWorkloadNameRegExp) +
				" environment variable." +
				" val: " + env2.NameRegExpForWorkload() +
				" trust: " + env2.SpiffeTrustDomain(),
		)
		return false
	}

	match := wre.FindStringSubmatch(spiffeid)
	if len(match) == 0 {
		return false
	}

	return strings.HasPrefix(spiffeid, prefix)
}

// IsSafe checks if a given SPIFFE ID belongs to VSecM Safe.
//
// A SPIFFE ID (SPIFFE IDentifier) is a URI that uniquely identifies a workload
// in a secure, interoperable way. This function verifies if the provided
// SPIFFE ID meets the criteria to be classified as a workload ID based on
// certain environmental settings.
//
// The function performs the following checks:
//  1. If the `spiffeid` starts with a "^", it assumed that it is a regular
//     expression pattern, it compiles the expression and checks if the SPIFFE
//     ID matches it.
//  2. Otherwise, it checks if the SPIFFE ID starts with the proper prefix.
//
// Parameters:
//
//	spiffeid (string): The SPIFFE ID to be checked.
//
// Returns:
//
//	bool: `true` if the SPIFFE ID belongs to VSecM Safe, `false` otherwise.
func IsSafe(spiffeid string) bool {
	if !IsWorkload(spiffeid) {
		return false
	}

	prefix := env2.SpiffeIdPrefixForSafe()

	if strings.HasPrefix(prefix, spiffeRegexPrefixStart) {
		re, err := regexp.Compile(prefix)
		if err != nil {
			panic(
				"Failed to compile the regular expression pattern " +
					"for Sentinel SPIFFE ID." +
					" Check the " + string(e.VSecMSpiffeIdPrefixSafe) +
					" environment variable." +
					" val: " + env2.SpiffeIdPrefixForSafe() +
					" trust: " + env2.SpiffeTrustDomain(),
			)
		}

		return re.MatchString(spiffeid)
	}

	return strings.HasPrefix(spiffeid, prefix)
}
