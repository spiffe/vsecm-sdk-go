// VMware Secrets Manager (VSecM) Go SDK -- https://vsecm.com
// Copyright 2024-present VSecM SDK contributors.
// SPDX-License-Identifier: Apache-2.0
// Keep your secrets... secret.

package backoff

import (
	"github.com/spiffe/vsecm-sdk-go/internal/debug"
	"math"
	"math/rand"
	"time"
)

// Strategy is a configuration for the backoff strategy to use when retrying
// operations.
type Strategy struct {
	// Maximum number of retries before giving up (inclusive)
	// Default is 10
	MaxRetries int64 // Maximum number of retries before giving up (inclusive)

	// Initial delay between retries (in milliseconds).
	Delay time.Duration

	// Whether to use exponential backoff or not (if false, constant delay
	// (plus a random jitter) is used)
	// Default is false
	Exponential bool
	// Maximum duration to wait between retries (in milliseconds)
	// Default is 10 seconds
	MaxWait time.Duration
}

// Retry implements a retry mechanism for a function that can fail
// (return an error).
// It accepts a scope for logging or identification purposes, a function that
// it will attempt to execute, and a strategy defining the behavior of the retry
// logic.
//
// The retry strategy allows for setting maximum retries, initial delay, whether
// to use exponential backoff, and a maximum duration for the delay. If
// exponential backoff is enabled, the delay between retries increases
// exponentially with each attempt, combined with a small randomization to
// prevent synchronization issues (thundering herd problem).
// If the function succeeds (returns nil), Retry will terminate early.
// If all retries are exhausted, the last error is returned.
//
// Params:
//
//	scope string - A descriptive name or identifier for the context of the retry
//	operation.
//	f func() error - The function to execute and retry if it fails.
//	s Strategy - Struct defining the retry parameters including maximum retries,
//	delay strategy, and max delay.
//
// Returns:
//
//	error - The last error returned by the function after all retries, or nil
//	if the function eventually succeeds.
//
// Example of usage:
//
//	err := Retry("database_connection", connectToDatabase, Strategy{
//	    MaxRetries: 5,
//	    Delay: 100,
//	    Exponential: true,
//	    MaxWait: 10 * time.Second,
//	})
//	if err != nil {
//	    fmt.Println("Failed to connect to database after retries:", err)
//	}
func Retry(scope string, f func() error, s Strategy) error {
	s = withDefaults(s)
	var err error

	debug.Log("Retry: starting retry loop")

	for i := 0; i <= int(s.MaxRetries); i++ {
		err = f()

		debug.Log("Retry: executed the function")

		if err == nil {
			debug.Log("Retry: success")
			return nil
		}

		var multiplier float64 = 1

		// if exponential backoff is enabled then delay increases exponentially:
		if s.Exponential {
			multiplier = math.Pow(2, float64(i))
		}

		sDelayMs := s.Delay.Milliseconds()
		if sDelayMs == 0 {
			sDelayMs = 10
		}

		delayMs := multiplier * float64(sDelayMs)
		delay := time.Duration(delayMs) * time.Millisecond

		// Some randomness to avoid the thundering herd problem.
		jitter := rand.Intn(int(sDelayMs))
		delay += time.Duration(jitter) * time.Millisecond
		if delay > s.MaxWait {
			delay = s.MaxWait
		}

		debug.Log("Retry: will sleep:", delay)

		time.Sleep(delay)

		debug.Log(
			"Retrying after", delay, "ms for the scope",
			scope, "-- attempt", i+1, "of", s.MaxRetries+1,
		)
	}

	return err
}

type Mode string

// withDefaults sets default values for the strategy if they are not set.
func withDefaults(s Strategy) Strategy {
	if s.MaxRetries == 0 {
		s.MaxRetries = 5
	}
	if s.Delay == 0 {
		s.Delay = 1000
	}
	if s.Exponential && s.MaxWait == 0 {
		s.MaxWait = 10 * time.Second
	}

	return s
}
