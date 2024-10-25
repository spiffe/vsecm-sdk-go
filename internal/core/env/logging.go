// VMware Secrets Manager (VSecM) Go SDK -- https://vsecm.com
// Copyright 2024-present VSecM SDK contributors.
// SPDX-License-Identifier: Apache-2.0
// Keep your secrets... secret.

package env

import (
	"github.com/spiffe/vsecm-sdk-go/internal/core/constants/env"
	"strconv"
)

type Level int

// Redefine log levels to avoid import cycle.
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

var level = struct {
	Off   Level
	Fatal Level
	Error Level
	Warn  Level
	Info  Level
	Audit Level
	Debug Level
	Trace Level
}{
	Off:   Off,
	Fatal: Fatal,
	Error: Error,
	Warn:  Warn,
	Info:  Info,
	Audit: Audit,
	Debug: Debug,
	Trace: Trace,
}

// LogLevel returns the value set by VSECM_LOG_LEVEL environment
// variable, or a default level.
//
// VSECM_LOG_LEVEL determines the verbosity of the logs.
// 0: logs are off, 7: highest verbosity (TRACE).
func LogLevel() int {
	p := env.Value(env.VSecMLogLevel)
	if p == "" {
		return int(level.Warn)
	}

	l, _ := strconv.Atoi(p)
	if l == int(level.Off) {
		return int(level.Warn)
	}

	if l < int(level.Off) || l > int(level.Trace) {
		return int(level.Warn)
	}

	return l
}
