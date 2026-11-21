// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sourcetokens

import (
	"bytes"
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
	tokens map[indexKey][]byte

	mu      sync.Mutex
	readers int
	retired bool
	zeroed  bool
}

type indexKey struct{ selector, source string }

// NewIndex builds an index from decoded token files. It copies their tokens:
// the caller still zeroes the files.
func NewIndex(files []*File) *Index {
	x := &Index{tokens: map[indexKey][]byte{}}
	for _, f := range files {
		x.put(f)
	}
	return x
}

func (x *Index) put(f *File) {
	for source, token := range f.Tokens {
		x.tokens[indexKey{f.Selector, source}] = bytes.Clone(token.Value)
	}
}

// withSelector returns a new index holding x's tokens with selector's
// replaced by f's (none when f is nil). x is unchanged and must not be
// retired meanwhile, which the Holder's lock guarantees.
func (x *Index) withSelector(selector string, f *File) *Index {
	next := &Index{tokens: make(map[indexKey][]byte, len(x.tokens))}
	for key, value := range x.tokens {
		if key.selector != selector {
			next.tokens[key] = bytes.Clone(value)
		}
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
	value, ok := x.tokens[indexKey{selector, source}]
	if !ok {
		return "", false
	}
	return string(value), true
}

// Names returns the source names with a token, by selector, each list
// sorted. The caller holds a reader of x. A nil index has none.
func (x *Index) Names() map[string][]string {
	out := map[string][]string{}
	if x == nil {
		return out
	}
	for key := range x.tokens {
		out[key.selector] = append(out[key.selector], key.source)
	}
	for _, names := range out {
		slices.Sort(names)
	}
	return out
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
	for _, value := range x.tokens {
		crypto.ZeroBytes(value)
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

// Names reads the source names with a token from the current index, by
// selector, holding a reader while it does. With no current index, as on a
// locked node, it returns none.
func (h *Holder) Names() map[string][]string {
	x, release := h.Acquire()
	defer release()
	return x.Names()
}

// TokenFor reads one token from the current index, holding a reader for the
// lookup. It has the shape externalcheck.TokenFor expects.
func (h *Holder) TokenFor(selector, source string) (string, bool) {
	x, release := h.Acquire()
	defer release()
	return x.TokenFor(selector, source)
}
