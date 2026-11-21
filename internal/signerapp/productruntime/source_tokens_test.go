// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package productruntime

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/keystore"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/sourcetokens"
)

// These tests anchor the source token index in KU2 of
// docs/FORMAL_TRACEABILITY.md: lock cleanup zeroes it only after the drain.

const sourceTokenTestKeyID = "MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ"

func sourceTokenIndex(t *testing.T, token string) *sourcetokens.Index {
	t.Helper()
	f, err := sourcetokens.SetToken(nil, sourceTokenTestKeyID, "screening", []byte(token), time.Unix(1_785_200_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Zero()
	return sourcetokens.NewIndex([]*sourcetokens.File{f})
}

// requireZeroed reads a retired index through a pointer the test kept, after
// the operation that zeroed it returned.
func requireZeroed(t *testing.T, x *sourcetokens.Index, what string) {
	t.Helper()
	got, ok := x.TokenFor(sourceTokenTestKeyID, "screening")
	if !ok || strings.Trim(got, "\x00") != "" {
		t.Fatalf("%s: the index still holds %q, want it zeroed", what, got)
	}
}

func TestLockZeroesTheSourceTokenIndexAfterTheDrain(t *testing.T) {
	ir := New(Config{})
	ir.SetUnlocked()
	index := sourceTokenIndex(t, "token-value")
	ir.PublishSourceTokens(index)

	// An external check step: a key use, then the token read inside it.
	stepCtx, release := ir.KeyUseContext(context.Background())
	if got, ok := ir.SourceTokenFor(sourceTokenTestKeyID, "screening"); !ok || got != "token-value" {
		t.Fatalf("SourceTokenFor() = %q, %v", got, ok)
	}
	lockDone := lockAsync(ir)
	waitClosed(t, stepCtx.Done(), "the lock to cancel the external check step")

	// The drain waits for the step, and the index is intact meanwhile.
	select {
	case <-lockDone:
		t.Fatal("Lock returned while the external check step held its key use")
	case <-time.After(50 * time.Millisecond):
	}
	if got, ok := index.TokenFor(sourceTokenTestKeyID, "screening"); !ok || got != "token-value" {
		t.Fatalf("the index was cleared under a registered key use: %q, %v", got, ok)
	}

	release()
	waitClosed(t, lockDone, "Lock to return after the step released")
	requireZeroed(t, index, "after the lock")
	if _, ok := ir.SourceTokenFor(sourceTokenTestKeyID, "screening"); ok {
		t.Fatal("SourceTokenFor() found a token while locked")
	}
}

// A token change publishes only in the session it began in: after a lock,
// or a lock and another unlock, the index is left to the next reload.
func TestReplaceSourceTokensPublishesOnlyInItsSession(t *testing.T) {
	ir := New(Config{})
	ir.SetUnlocked()
	ir.PublishSourceTokens(sourceTokenIndex(t, "first"))
	generation, unlocked := ir.UnlockedGeneration()
	if !unlocked {
		t.Fatal("not unlocked")
	}
	f, err := sourcetokens.SetToken(nil, sourceTokenTestKeyID, "screening", []byte("second"), time.Unix(1_785_200_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Zero()
	if !ir.ReplaceSourceTokens(generation, sourceTokenTestKeyID, f) {
		t.Fatal("ReplaceSourceTokens() refused in its own session")
	}
	if got, ok := ir.SourceTokenFor(sourceTokenTestKeyID, "screening"); !ok || got != "second" {
		t.Fatalf("SourceTokenFor() after the replace = %q, %v", got, ok)
	}

	ir.Lock()
	if ir.ReplaceSourceTokens(generation, sourceTokenTestKeyID, f) {
		t.Fatal("ReplaceSourceTokens() published while locked")
	}
	if _, ok := ir.SourceTokenFor(sourceTokenTestKeyID, "screening"); ok {
		t.Fatal("a refused replace left an index while locked")
	}
	ir.SetUnlocked()
	if ir.ReplaceSourceTokens(generation, sourceTokenTestKeyID, f) {
		t.Fatal("ReplaceSourceTokens() published in a later session")
	}
	if ir.ReplaceSourceTokens(generation+1000, sourceTokenTestKeyID, nil) {
		t.Fatal("ReplaceSourceTokens() published in a session that never was")
	}
}

func TestDestroyZeroesTheSourceTokenIndex(t *testing.T) {
	ir := New(Config{})
	ir.SetUnlocked()
	index := sourceTokenIndex(t, "token-value")
	ir.PublishSourceTokens(index)
	ir.Destroy()
	requireZeroed(t, index, "after Destroy")
	if _, ok := ir.SourceTokenFor(sourceTokenTestKeyID, "screening"); ok {
		t.Fatal("SourceTokenFor() found a token after Destroy")
	}
}

// A reload that publishes the index and then fails, as an unlock's can when a
// step after the policy load fails, leaves no tokens in memory: the unlock
// failed and the signer stays locked.
func TestAFailedUnlockReloadLeavesNoSourceTokens(t *testing.T) {
	ir := New(Config{})
	var published *sourcetokens.Index
	ir.SetReloadFunc(func([]byte, *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		published = sourceTokenIndex(t, "token-value")
		ir.PublishSourceTokens(published)
		return nil, errors.New("injected failure after the policy load")
	})
	if _, err := ir.ReloadWithPassphrase([]byte("passphrase")); err == nil {
		t.Fatal("ReloadWithPassphrase() succeeded")
	}
	requireZeroed(t, published, "after the failed reload")
	if _, ok := ir.SourceTokenFor(sourceTokenTestKeyID, "screening"); ok {
		t.Fatal("SourceTokenFor() found a token after a failed unlock reload")
	}
}
