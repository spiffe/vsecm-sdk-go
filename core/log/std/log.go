// VMware Secrets Manager (VSecM) Go SDK -- https://vsecm.com
// Copyright 2024-present VSecM SDK contributors.
// SPDX-License-Identifier: Apache-2.0
// Keep your secrets... secret.

// Package std provides a simple and flexible logging library with various
// log levels.
package std

import "github.com/spiffe/vsecm-sdk-go/core/log/level"

// InfoLn logs an info level message.
func InfoLn(correlationID *string, v ...any) {
	logMessage(level.Info, "[INFO]", correlationID, v...)
}

// TraceLn logs a trace level message.
func TraceLn(correlationID *string, v ...any) {
	logMessage(level.Trace, "[TRACE]", correlationID, v...)
}
