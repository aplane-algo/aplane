// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sourcetokens

import (
	"bytes"
	"maps"
	"slices"
	"sync"

	"github.com/aplane-algo/aplane/internal/crypto"
)

// Index is an immutable snapshot of a node's tokens, keyed by policy
// selector and source name. Its token bytes are its own: building it copies
// them, and nothing changes them until it is zeroed.
//
// An index is never zeroed in place while a reader may hold it. Each index
// counts its readers; it is zeroed once it has been retired (a reload, a set
// or a remove published another, or a lock cleared it) and its last reader
// has released.
type Index struct {
	// tokens is by selector, then by source name.
	tokens map[string]map[string][]byte

	mu      sync.Mutex
	readers int
	retired bool
	zeroed  bool
}

// NewIndex builds an index from decoded token files. It copies their tokens:
// the caller still zeroes the files.
func NewIndex(files []*File) *Index {
	x := &Index{tokens: map[string]map[string][]byte{}}
	for _, f := range files {
		x.put(f)
	}
	return x
}

func (x *Index) put(f *File) {
	sources := make(map[string][]byte, len(f.Tokens))
	for source, token := range f.Tokens {
		sources[source] = bytes.Clone(token.Value)
	}
	x.tokens[f.Selector] = sources
}

// withSelector returns a new index holding x's tokens with selector's
// replaced by f's (none when f is nil). x is unchanged and must not be
// retired meanwhile, which the Holder's lock guarantees.
func (x *Index) withSelector(selector string, f *File) *Index {
	next := &Index{tokens: make(map[string]map[string][]byte, len(x.tokens))}
	for other, sources := range x.tokens {
		if other == selector {
			continue
		}
		copied := make(map[string][]byte, len(sources))
		for source, value := range sources {
			copied[source] = bytes.Clone(value)
		}
		next.tokens[other] = copied
	}
	if f != nil {
		next.put(f)
	}
	return next
}

// TokenFor returns the token set for source under selector, and false when
// none is set. The caller holds a reader of x (Holder.Acquire). The token is
// returned as a Go string, which cannot be zeroed: the external check places
// it in a request header, where it stays until the request is garbage
// collected. Zeroing covers the index, not those copies.
func (x *Index) TokenFor(selector, source string) (string, bool) {
	if x == nil {
		return "", false
	}
	value, ok := x.tokens[selector][source]
	if !ok {
		return "", false
	}
	return string(value), true
}

// NamesFor returns the source names selector has a token for, sorted, and
// known: false only for a nil index, as a locked node has, which does not
// know which tokens are set. A selector without tokens in a published index
// has none, known. The caller holds a reader of x.
func (x *Index) NamesFor(selector string) ([]string, bool) {
	if x == nil {
		return nil, false
	}
	return slices.Sorted(maps.Keys(x.tokens[selector])), true
}

func (x *Index) acquire() {
	x.mu.Lock()
	x.readers++
	x.mu.Unlock()
}

func (x *Index) release() {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.readers--
	if x.readers == 0 && x.retired {
		x.zeroLocked()
	}
}

// retire marks x replaced and zeroes it at once when nobody reads it.
func (x *Index) retire() {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.retired = true
	if x.readers == 0 {
		x.zeroLocked()
	}
}

func (x *Index) zeroLocked() {
	if x.zeroed {
		return
	}
	for _, sources := range x.tokens {
		for _, value := range sources {
			crypto.ZeroBytes(value)
		}
	}
	x.zeroed = true
}

// Holder publishes a node's current token index. It is safe for concurrent
// use. Its zero value holds no index, as a locked node has none.
type Holder struct {
	mu      sync.Mutex
	current *Index
}

// Publish installs next as the current index, nil for none, and retires the
// one it replaces.
func (h *Holder) Publish(next *Index) {
	h.mu.Lock()
	old := h.current
	h.current = next
	h.mu.Unlock()
	if old != nil {
		old.retire()
	}
}

// Replace publishes a copy of the current index with selector's tokens
// replaced by f's (removed when f is nil), and retires the old index. With no
// current index it publishes one holding f alone. f is copied: the caller
// still zeroes it.
func (h *Holder) Replace(selector string, f *File) {
	h.mu.Lock()
	old := h.current
	base := old
	if base == nil {
		base = NewIndex(nil)
	}
	h.current = base.withSelector(selector, f)
	h.mu.Unlock()
	if old != nil {
		old.retire()
	}
}

// Clear retires the current index and leaves none. A lock clears the index
// after every key user has released, so nothing reads it and it is zeroed at
// once.
func (h *Holder) Clear() { h.Publish(nil) }

// Acquire returns the current index with a reader registered, and the
// release that ends it, which is idempotent. The index stays intact until
// release, whatever is published meanwhile. With no current index it returns
// nil and a no-op release.
func (h *Holder) Acquire() (*Index, func()) {
	h.mu.Lock()
	x := h.current
	if x == nil {
		h.mu.Unlock()
		return nil, func() {}
	}
	// Registered under h.mu, while x is still current: no Publish can retire
	// it in between.
	x.acquire()
	h.mu.Unlock()
	var once sync.Once
	return x, func() { once.Do(x.release) }
}

// NamesFor reads the source names selector has a token for from the current
// index, holding a reader while it does. known is false with no current
// index, as on a locked node: which tokens are set is not known.
func (h *Holder) NamesFor(selector string) (names []string, known bool) {
	x, release := h.Acquire()
	defer release()
	return x.NamesFor(selector)
}

// TokenFor reads one token from the current index, holding a reader for the
// lookup. It has the shape externalcheck.TokenFor expects.
func (h *Holder) TokenFor(selector, source string) (string, bool) {
	x, release := h.Acquire()
	defer release()
	return x.TokenFor(selector, source)
}
