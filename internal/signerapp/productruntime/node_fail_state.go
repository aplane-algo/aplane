// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package productruntime

import (
	"errors"
	"fmt"
	"sync"
)

// ErrNodeFailClosed marks a process-wide invariant failure that requires a
// restart after operator repair.
var ErrNodeFailClosed = errors.New("signer node fail closed")

// NodeFailState publishes the first process-wide fail-closed error.
type NodeFailState struct {
	mu  sync.RWMutex
	err error
}

// Fail records the first failure and leaves it sticky for the process lifetime.
func (s *NodeFailState) Fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return
	}
	if err == nil {
		s.err = ErrNodeFailClosed
		return
	}
	s.err = fmt.Errorf("%w: %w", ErrNodeFailClosed, err)
}

// Err reports the fail-closed reason, if one has been published.
func (s *NodeFailState) Err() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.err
}
