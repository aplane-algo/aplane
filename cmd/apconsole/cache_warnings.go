// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/aplane-algo/aplane/internal/termsafe"
)

// cacheWarnings keeps cache warnings visible while apconsole discards the cache
// log, which would otherwise hide a report of cache tampering. Shell startup
// loads the caches before any pane exists, and a network switch reloads them
// during the session, so warnings are held for the shell pane until it attaches
// and delivered live afterwards.
//
// Each warning raised before attach also goes to the terminal's stderr. The pane
// may never show it: startup can fail, or the node can have no shell pane. Text
// written before the alternate screen opens is on screen again once it closes.
type cacheWarnings struct {
	stderr io.Writer

	mu      sync.Mutex
	pending []string
	deliver func(line string)
}

// consoleCacheWarnings holds the real stderr, taken before apconsole points
// os.Stderr at /dev/null for the TUI.
var consoleCacheWarnings = newCacheWarnings(os.Stderr)

func newCacheWarnings(stderr io.Writer) *cacheWarnings {
	return &cacheWarnings{stderr: stderr}
}

// add records one warning. It may be called from any goroutine.
func (c *cacheWarnings) add(message string) {
	line := "[cache] warning: " + termsafe.Line(message)

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.deliver != nil {
		c.deliver(line)
		return
	}
	c.pending = append(c.pending, line)
	_, _ = fmt.Fprintln(c.stderr, line)
}

// takeStartup returns the warnings raised so far, for the pane's first lines.
func (c *cacheWarnings) takeStartup() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	lines := c.pending
	c.pending = nil
	return lines
}

// attach sends later warnings to deliver, which must not block. Anything raised
// since takeStartup goes first.
func (c *cacheWarnings) attach(deliver func(line string)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, line := range c.pending {
		deliver(line)
	}
	c.pending = nil
	c.deliver = deliver
}
