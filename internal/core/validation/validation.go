// VMware Secrets Manager (VSecM) Go SDK -- https://vsecm.com
// Copyright 2024-present VSecM SDK contributors.
// SPDX-License-Identifier: Apache-2.0
// Keep your secrets... secret.

package validation

import (
	"regexp"
	"strings"

	e "github.com/spiffe/vsecm-sdk-go/internal/core/constants/env"
	"github.com/spiffe/vsecm-sdk-go/internal/core/env"
)

// Any SPIFFE ID regular expression matcher shall start with the
// `^spiffe://$trustDomain` prefix for extra security.
//
// This variable shall be treated as constant and should not be modified.
var spiffeRegexPrefixStart = "^spiffe://" + env.SpiffeTrustDomain() + "/"
var spiffeIdPrefixStart = "spiffe://" + env.SpiffeTrustDomain() + "/"

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
	prefix := env.SpiffeIdPrefixForWorkload()

	if strings.HasPrefix(prefix, spiffeRegexPrefixStart) {
		re, err := regexp.Compile(prefix)
		if err != nil {
			panic(
				"Failed to compile the regular expression pattern " +
					"for SPIFFE ID." +
					" Check the " + string(e.VSecMSpiffeIdPrefixWorkload) +
					" environment variable. " +
					" val: " + env.SpiffeIdPrefixForWorkload() +
					" trust: " + env.SpiffeTrustDomain(),
			)
			return false
		}

		nrw := env.NameRegExpForWorkload()
		wre, err := regexp.Compile(nrw)
		if err != nil {
			panic(
				"Failed to compile the regular expression pattern " +
					"for SPIFFE ID." +
					" Check the " + string(e.VSecMWorkloadNameRegExp) +
					" environment variable." +
					" val: " + env.NameRegExpForWorkload() +
					" trust: " + env.SpiffeTrustDomain(),
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

	nrw := env.NameRegExpForWorkload()
	if !strings.HasPrefix(nrw, spiffeRegexPrefixStart) {

		// Insecure configuration detected.
		// Panic to prevent further issues:
		panic(
			"Invalid regular expression pattern for SPIFFE ID." +
				" Expected: ^spiffe://<trust_domain>/..." +
				" Check the " + string(e.VSecMWorkloadNameRegExp) +
				" environment variable." +
				" val: " + env.NameRegExpForWorkload() +
				" trust: " + env.SpiffeTrustDomain(),
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
				" val: " + env.NameRegExpForWorkload() +
				" trust: " + env.SpiffeTrustDomain(),
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

	prefix := env.SpiffeIdPrefixForSafe()

	if strings.HasPrefix(prefix, spiffeRegexPrefixStart) {
		re, err := regexp.Compile(prefix)
		if err != nil {
			panic(
				"Failed to compile the regular expression pattern " +
					"for Sentinel SPIFFE ID." +
					" Check the " + string(e.VSecMSpiffeIdPrefixSafe) +
					" environment variable." +
					" val: " + env.SpiffeIdPrefixForSafe() +
					" trust: " + env.SpiffeTrustDomain(),
			)
		}

		return re.MatchString(spiffeid)
	}

	return strings.HasPrefix(spiffeid, prefix)
}

// IsClerk determines if a given SPIFFE ID belongs to a clerk workload in the
// VSecM system.
//
// A clerk in VSecM is a workload that has elevated permissions to perform
// certain secret management operations. This function validates whether a
// given SPIFFE ID matches the configured pattern for clerk workloads.
//
// The function supports both direct prefix matching and regular expression
// patterns. When the configured prefix starts with the regex prefix marker,
// the rest of the pattern is treated as a regular expression.
//
// Parameters:
//   - spiffeid: The SPIFFE ID string to validate (e.g.,
//     "spiffe://example.org/clerk/service")
//
// Returns:
//   - bool: true if the SPIFFE ID belongs to a clerk workload, false otherwise
//
// The function will panic if:
//   - The configured clerk SPIFFE ID prefix is an invalid regular expression
//     pattern
//   - The VSecM_SPIFFE_ID_PREFIX_CLERK environment variable contains an invalid
//     pattern
//
// The validation process:
//  1. First checks if the ID is a valid workload ID using IsWorkload()
//  2. Then validates against the clerk-specific prefix pattern
//
// Example:
//
//	id := "spiffe://example.org/clerk/service"
//	if IsClerk(id) {
//	    // Proceed with clerk-specific operations
//	}
//
// Note: This function is critical for VSecM's security model as it gates access
// to elevated secret management operations. The clerk prefix pattern should be
// carefully configured through the appropriate environment variables.
func IsClerk(spiffeid string) bool {
	if !IsWorkload(spiffeid) {
		return false
	}

	prefix := env.SpiffeIdPrefixForClerk()

	if strings.HasPrefix(prefix, spiffeRegexPrefixStart) {
		re, err := regexp.Compile(prefix)
		if err != nil {
			panic(
				"Failed to compile the regular expression pattern " +
					"for Sentinel SPIFFE ID." +
					" Check the " + string(e.VSecMSpiffeIdPrefixClerk) +
					" environment variable." +
					" val: " + env.SpiffeIdPrefixForClerk() +
					" trust: " + env.SpiffeTrustDomain(),
			)
		}

		return re.MatchString(spiffeid)
	}

	return strings.HasPrefix(spiffeid, prefix)
}
