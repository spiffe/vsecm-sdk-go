// VMware Secrets Manager (VSecM) Go SDK -- https://vsecm.com
// Copyright 2024-present VSecM SDK contributors.
// SPDX-License-Identifier: Apache-2.0
// Keep your secrets... secret.

package template

import (
	"github.com/spiffe/vsecm-sdk-go/internal/core/constants/symbol"
	"github.com/spiffe/vsecm-sdk-go/internal/core/constants/val"
	"strings"
)

// removeKeyValueWithNoValue takes an input string containing key-value pairs
// and filters out pairs where the value is "<no value>". It splits the input
// string into key-value pairs, iterates through them, and retains only the
// pairs with values that are not equal to "<no value>".
// The function then joins the filtered pairs back into a string and returns the
// resulting string. This function effectively removes key-value pairs with
// "<no value>" from the input string. Helpful for data cleaning and filtering
// when you want to omit certain key/value pairs from a template.
func removeKeyValueWithNoValue(input string) string {
	// Split the input string into key-value pairs
	pairs := strings.Split(input, symbol.ItemSeparator)

	// Initialize a slice to store the filtered pairs
	var filteredPairs []string

	for _, pair := range pairs {
		keyValue := strings.SplitN(pair, symbol.Separator, 2)
		if len(keyValue) == 2 && keyValue[1] != val.JsonEmpty {
			// Add the pair to the filtered pairs if the value is not
			// "<no value>"
			filteredPairs = append(filteredPairs, pair)
		}
	}

	// Join the filtered pairs back into a string
	result := strings.Join(filteredPairs, ",")
	return result
}
