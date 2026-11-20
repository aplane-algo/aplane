// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"maps"
	"slices"
	"sync"

	"github.com/aplane-algo/aplane/internal/cosigner/cosignerrefs"
)

// invalidReferenceReport logs the cosigner reference entries a key type list
// leaves out only when they change. Clients may list key types often, and
// each listing would otherwise log the same entries again.
type invalidReferenceReport struct {
	mu   sync.Mutex
	last map[string]string // entry path -> its report as last logged
}

// report logs each entry that is new or reported differently, and each one
// last logged that is no longer left out.
func (r *invalidReferenceReport) report(invalid []cosignerrefs.InvalidRecord, warnf, infof func(format string, args ...any)) {
	current := make(map[string]string, len(invalid))
	for _, bad := range invalid {
		current[bad.Path] = bad.String()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, bad := range invalid {
		if r.last[bad.Path] != current[bad.Path] {
			warnf("cosigner reference file left out of the key type list: %s", current[bad.Path])
		}
	}
	for _, path := range slices.Sorted(maps.Keys(r.last)) {
		if _, ok := current[path]; !ok {
			infof("cosigner reference file %q is no longer left out of the key type list", path)
		}
	}
	r.last = current
}
