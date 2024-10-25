// VMware Secrets Manager (VSecM) Go SDK -- https://vsecm.com
// Copyright 2024-present VSecM SDK contributors.
// SPDX-License-Identifier: Apache-2.0
// Keep your secrets... secret.

package level

import (
	"sync"

	"github.com/spiffe/vsecm-sdk-go/core/env"
)

// Level represents log levels.
type Level int

// Define log levels as constants.
const (
	Off Level = iota
	Fatal
	Error
	Warn
	Info
	Audit
	Debug
	Trace
)

var mux sync.RWMutex // Protects access to currentLevel.

// Initialize currentLevel with the value from the environment.
var currentLevel = Level(env.LogLevel())

// Get retrieves the current global log level.
func Get() Level {
	mux.RLock()
	defer mux.RUnlock()

	return currentLevel
}
