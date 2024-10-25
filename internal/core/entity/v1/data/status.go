// VMware Secrets Manager (VSecM) Go SDK -- https://vsecm.com
// Copyright 2024-present VSecM SDK contributors.
// SPDX-License-Identifier: Apache-2.0
// Keep your secrets... secret.

package data

import "sync"

// InitStatus is the initialization status of VSecM Sentinel
// and other VSecM components.
type InitStatus string

var (
	Pending InitStatus = "pending"
	Ready   InitStatus = "ready"
)

// Status is a struct representing the current state of the secret manager,
// including the lengths and capacities of the secret queues and the total
// number of secrets stored.
type Status struct {
	SecretQueueLen int
	SecretQueueCap int
	K8sQueueLen    int
	K8sQueueCap    int
	NumSecrets     int
	Lock           sync.RWMutex
}

// Increment is a method for the Status struct that increments the NumSecrets
// field by 1 if the provided secret name is not found in the in-memory store.
func (s *Status) Increment(name string, loader func(name any) (any, bool)) {
	s.Lock.Lock()
	defer s.Lock.Unlock()
	_, ok := loader(name)
	if !ok {
		s.NumSecrets++
	}
}

// Decrement is a method for the Status struct that decrements the NumSecrets
// field by 1 if the provided secret name is found in the in-memory store.
func (s *Status) Decrement(name string, loader func(name any) (any, bool)) {
	s.Lock.Lock()
	defer s.Lock.Unlock()
	_, ok := loader(name)
	if ok {
		s.NumSecrets--
	}
}
