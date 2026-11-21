// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sourcetokens

import (
	"fmt"
	"sync"
	"testing"
)

// zeroed reports whether every token byte of x is zero and x says it was
// zeroed.
func zeroed(t *testing.T, x *Index) bool {
	t.Helper()
	x.mu.Lock()
	defer x.mu.Unlock()
	for key, value := range x.tokens {
		for _, c := range value {
			if c != 0 && x.zeroed {
				t.Fatalf("index says it is zeroed but the token of %v is not", key)
			}
		}
	}
	return x.zeroed
}

func indexOf(t *testing.T, tokens map[string]string) *Index {
	t.Helper()
	var f *File
	for source, value := range tokens {
		f = mustSet(t, f, testKeyID, source, value)
	}
	defer f.Zero()
	return NewIndex([]*File{f})
}

func TestNewIndexOwnsItsTokens(t *testing.T) {
	f := mustSet(t, nil, testKeyID, "ops", "token")
	x := NewIndex([]*File{f})
	f.Zero()
	if got, ok := x.TokenFor(testKeyID, "ops"); !ok || got != "token" {
		t.Fatalf("TokenFor() after the file was zeroed = %q, %v", got, ok)
	}
}

func TestPublishZeroesTheReplacedIndexOnlyAfterItsLastReader(t *testing.T) {
	var h Holder
	first := indexOf(t, map[string]string{"ops": "one"})
	h.Publish(first)

	held, release := h.Acquire()
	if held != first {
		t.Fatal("Acquire() did not return the current index")
	}
	_, releaseOther := h.Acquire()
	h.Publish(indexOf(t, map[string]string{"ops": "two"}))

	// Replaced but held: intact, and its reader still reads its own token.
	if zeroed(t, first) {
		t.Fatal("a replaced index was zeroed while readers held it")
	}
	if got, ok := held.TokenFor(testKeyID, "ops"); !ok || got != "one" {
		t.Fatalf("held index TokenFor() = %q, %v; want the token it was built with", got, ok)
	}
	// New readers get the new index.
	if got, ok := h.TokenFor(testKeyID, "ops"); !ok || got != "two" {
		t.Fatalf("Holder.TokenFor() = %q, %v; want the new index's token", got, ok)
	}
	release()
	release() // idempotent: it does not release the other reader
	if zeroed(t, first) {
		t.Fatal("the index was zeroed while its second reader held it")
	}
	releaseOther()
	if !zeroed(t, first) {
		t.Fatal("the replaced index was not zeroed when its last reader released")
	}
}

func TestPublishZeroesAnUnreadReplacedIndexAtOnce(t *testing.T) {
	var h Holder
	first := indexOf(t, map[string]string{"ops": "one"})
	h.Publish(first)
	_, release := h.Acquire()
	release()
	if zeroed(t, first) {
		t.Fatal("the current index was zeroed when a reader released")
	}
	h.Publish(nil)
	if !zeroed(t, first) {
		t.Fatal("a replaced index nobody reads was not zeroed")
	}
}

func TestClearLeavesNoIndex(t *testing.T) {
	var h Holder
	first := indexOf(t, map[string]string{"ops": "one"})
	h.Publish(first)
	h.Clear()
	if !zeroed(t, first) {
		t.Fatal("Clear() did not zero the index")
	}
	if x, release := h.Acquire(); x != nil {
		release()
		t.Fatal("Acquire() returned an index after Clear()")
	}
	if _, ok := h.TokenFor(testKeyID, "ops"); ok {
		t.Fatal("TokenFor() found a token after Clear()")
	}
	h.Clear() // clearing twice is a no-op
}

func TestReplaceSwapsOneSelectorAndKeepsTheRest(t *testing.T) {
	var h Holder
	keyFile := mustSet(t, nil, testKeyID, "ops", "key-token")
	defaultFile := mustSet(t, nil, DefaultSelector, "ops", "default-token")
	first := NewIndex([]*File{keyFile, defaultFile})
	h.Publish(first)
	held, release := h.Acquire()

	replacement := mustSet(t, nil, testKeyID, "screening", "new-token")
	h.Replace(testKeyID, replacement)
	replacement.Zero() // the holder copied it
	if got, ok := h.TokenFor(testKeyID, "screening"); !ok || got != "new-token" {
		t.Fatalf("TokenFor(replaced selector) = %q, %v", got, ok)
	}
	if _, ok := h.TokenFor(testKeyID, "ops"); ok {
		t.Fatal("Replace() kept a token of the replaced selector")
	}
	if got, ok := h.TokenFor(DefaultSelector, "ops"); !ok || got != "default-token" {
		t.Fatalf("TokenFor(other selector) = %q, %v", got, ok)
	}
	if got, ok := held.TokenFor(testKeyID, "ops"); !ok || got != "key-token" || zeroed(t, first) {
		t.Fatalf("held index after Replace() = %q, %v", got, ok)
	}
	release()
	if !zeroed(t, first) {
		t.Fatal("the index Replace() retired was not zeroed after its reader released")
	}

	h.Replace(testKeyID, nil)
	if _, ok := h.TokenFor(testKeyID, "screening"); ok {
		t.Fatal("Replace(nil) left the selector's tokens")
	}
	if _, ok := h.TokenFor(DefaultSelector, "ops"); !ok {
		t.Fatal("Replace(nil) removed another selector's tokens")
	}

	var empty Holder
	empty.Replace(DefaultSelector, defaultFile)
	if got, ok := empty.TokenFor(DefaultSelector, "ops"); !ok || got != "default-token" {
		t.Fatalf("Replace() with no index = %q, %v", got, ok)
	}
}

// Readers, publishers and a clear run together; run with -race. Every
// reader sees a whole token from some index, never a zeroed one.
func TestHolderIsSafeForConcurrentUse(t *testing.T) {
	var h Holder
	h.Publish(indexOf(t, map[string]string{"ops": "token-0"}))
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				x, release := h.Acquire()
				got, ok := x.TokenFor(testKeyID, "ops")
				if ok && (len(got) < len("token-0") || got[0] != 't') {
					t.Errorf("a reader saw a damaged token %q", got)
				}
				release()
				if got, ok := h.TokenFor(testKeyID, "ops"); ok && got[0] != 't' {
					t.Errorf("TokenFor() saw a damaged token %q", got)
				}
			}
		}()
	}
	for i := range 200 {
		f := mustSet(t, nil, testKeyID, "ops", fmt.Sprintf("token-%d", i))
		switch i % 3 {
		case 0:
			h.Publish(NewIndex([]*File{f}))
		case 1:
			h.Replace(testKeyID, f)
		default:
			h.Clear()
		}
		f.Zero()
	}
	close(stop)
	wg.Wait()
}
