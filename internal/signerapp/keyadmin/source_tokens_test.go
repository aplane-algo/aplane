// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyadmin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/sourcetokens"
	"github.com/aplane-algo/aplane/internal/witness"
)

const unheldWitnessKeyID = "AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPQ"

// cosignerWithKey is an unlocked cosigner runtime holding one cosigner key.
func cosignerWithKey(t *testing.T) (Service, string) {
	t.Helper()
	ir := setupProductRuntimeWithRole(t, noderole.RoleCosigner)
	svc := Service{Runtime: ir, MutationLock: &recordingLock{}}
	result, err := svc.GenerateKey(context.Background(), witness.Falcon1024V1, nil)
	if err != nil {
		t.Fatalf("GenerateKey(cosigner) error = %#v", err)
	}
	return svc, result.Address
}

func readTokenFile(t *testing.T, svc Service, selector string) (*sourcetokens.File, bool) {
	t.Helper()
	active, err := svc.Runtime.ActivePaths()
	if err != nil {
		t.Fatal(err)
	}
	var f *sourcetokens.File
	var ok bool
	if err := svc.Runtime.WithKeyring(func(kr *crypto.Keyring) error {
		var readErr error
		f, ok, readErr = sourcetokens.ReadFile(active, selector, kr)
		return readErr
	}); err != nil {
		t.Fatal(err)
	}
	return f, ok
}

func TestSetSourceTokenWritesTheFileAndPublishesTheIndex(t *testing.T) {
	svc, keyID := cosignerWithKey(t)
	listing, svcErr := svc.SetSourceToken(keyID, "screening", []byte("first-token"))
	if svcErr != nil {
		t.Fatalf("SetSourceToken() error = %#v", svcErr)
	}
	if len(listing) != 1 || listing[0].Source != "screening" || listing[0].SetAt.IsZero() {
		t.Fatalf("SetSourceToken() listing = %+v", listing)
	}
	if got, ok := svc.Runtime.SourceTokenFor(keyID, "screening"); !ok || got != "first-token" {
		t.Fatalf("SourceTokenFor() = %q, %v", got, ok)
	}
	active, err := svc.Runtime.ActivePaths()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(active.SourceTokenPath(keyID))
	if err != nil || strings.Contains(string(raw), "first-token") {
		t.Fatalf("token file = %v; it must exist and hold no token in the clear", err)
	}

	// Another source, and the same source replaced.
	if _, svcErr := svc.SetSourceToken(keyID, "ops", []byte("ops-token")); svcErr != nil {
		t.Fatalf("SetSourceToken(second source) error = %#v", svcErr)
	}
	listing, svcErr = svc.SetSourceToken(keyID, "screening", []byte("second-token"))
	if svcErr != nil || len(listing) != 2 || listing[0].Source != "ops" || listing[1].Source != "screening" {
		t.Fatalf("SetSourceToken(replace) = %+v, %#v", listing, svcErr)
	}
	f, ok := readTokenFile(t, svc, keyID)
	defer f.Zero()
	if !ok || string(f.Tokens["screening"].Value) != "second-token" || string(f.Tokens["ops"].Value) != "ops-token" {
		t.Fatalf("token file after the replace = %+v", f.Listing())
	}
	if got, _ := svc.Runtime.SourceTokenFor(keyID, "screening"); got != "second-token" {
		t.Fatalf("SourceTokenFor() after the replace = %q", got)
	}

	// The node default's tokens need no key.
	if _, svcErr := svc.SetSourceToken(sourcetokens.DefaultSelector, "screening", []byte("default-token")); svcErr != nil {
		t.Fatalf("SetSourceToken(default) error = %#v", svcErr)
	}
	if got, _ := svc.Runtime.SourceTokenFor(sourcetokens.DefaultSelector, "screening"); got != "default-token" {
		t.Fatalf("SourceTokenFor(default) = %q", got)
	}
	if got, _ := svc.Runtime.SourceTokenFor(keyID, "screening"); got != "second-token" {
		t.Fatalf("setting the default's token changed a key's: %q", got)
	}
}

func TestSetSourceTokenRefusals(t *testing.T) {
	svc, keyID := cosignerWithKey(t)
	for i := range sourcetokens.MaxTokens {
		if _, svcErr := svc.SetSourceToken(keyID, fmt.Sprintf("s%d", i), []byte("t")); svcErr != nil {
			t.Fatalf("SetSourceToken(%d) error = %#v", i, svcErr)
		}
	}
	long := strings.Repeat("x", sourcetokens.MaxTokenBytes)
	tests := []struct {
		name     string
		selector string
		source   string
		token    string
		wantKind ErrorKind
	}{
		{"a key the node does not hold", unheldWitnessKeyID, "screening", "t", ErrorNotFound},
		{"an address", "CEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEI7JH2AYM", "screening", "t", ErrorInvalidInput},
		{"a ninth token", keyID, "s8", "t", ErrorInvalidInput},
		{"a token with a space", sourcetokens.DefaultSelector, "screening", "Bearer secret-value", ErrorInvalidInput},
		{"a token with a newline", sourcetokens.DefaultSelector, "screening", "secret-value\r\nX: y", ErrorInvalidInput},
		{"an empty token", sourcetokens.DefaultSelector, "screening", "", ErrorInvalidInput},
		{"a bad source name", sourcetokens.DefaultSelector, "Screening", "t", ErrorInvalidInput},
		{"a file over the size limit", sourcetokens.DefaultSelector, "s2", long, ErrorInvalidInput},
	}
	// Two long tokens fit; a third does not.
	for _, source := range []string{"s0", "s1"} {
		if _, svcErr := svc.SetSourceToken(sourcetokens.DefaultSelector, source, []byte(long)); svcErr != nil {
			t.Fatalf("SetSourceToken(long %s) error = %#v", source, svcErr)
		}
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, svcErr := svc.SetSourceToken(tt.selector, tt.source, []byte(tt.token))
			if svcErr == nil || svcErr.Kind != tt.wantKind {
				t.Fatalf("SetSourceToken() error = %#v, want kind %v", svcErr, tt.wantKind)
			}
			if strings.Contains(svcErr.Message, "secret-value") || (len(tt.token) > 8 && strings.Contains(svcErr.Message, tt.token)) {
				t.Fatalf("the error quotes the token: %s", svcErr.Message)
			}
		})
	}
	if _, ok := svc.Runtime.SourceTokenFor(unheldWitnessKeyID, "screening"); ok {
		t.Fatal("a refused set published a token")
	}
	f, _ := readTokenFile(t, svc, sourcetokens.DefaultSelector)
	defer f.Zero()
	if len(f.Tokens) != 2 {
		t.Fatalf("the default's file after the refused sets = %+v, want its two tokens", f.Listing())
	}
}

func TestSourceTokensAreRefusedOnASignerNode(t *testing.T) {
	ir := setupProductRuntimeWithRole(t, noderole.RoleSigner)
	svc := Service{Runtime: ir}
	if _, svcErr := svc.SetSourceToken(sourcetokens.DefaultSelector, "screening", []byte("t")); svcErr == nil || svcErr.Kind != ErrorInvalidInput {
		t.Fatalf("SetSourceToken(signer) error = %#v", svcErr)
	}
	if _, svcErr := svc.RemoveSourceToken(sourcetokens.DefaultSelector, "screening"); svcErr == nil || svcErr.Kind != ErrorInvalidInput {
		t.Fatalf("RemoveSourceToken(signer) error = %#v", svcErr)
	}
	active, err := ir.ActivePaths()
	if err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(active.SourceTokensDir()); err != nil || len(entries) != 0 {
		t.Fatalf("source tokens on a signer node = %v, %v", entries, err)
	}
}

// A token change is a key write: recovery refuses it as a lock does, and it
// writes nothing (RB2 in docs/FORMAL_TRACEABILITY.md).
func TestSourceTokenChangesRefuseWhileLocked(t *testing.T) {
	for name, leave := range map[string]func(svc Service){
		"locked":   func(svc Service) { svc.Runtime.Lock() },
		"recovery": func(svc Service) { svc.Runtime.EnterRecovery(nil) },
	} {
		t.Run(name, func(t *testing.T) {
			svc, keyID := cosignerWithKey(t)
			if _, svcErr := svc.SetSourceToken(keyID, "screening", []byte("t")); svcErr != nil {
				t.Fatal(svcErr)
			}
			active, err := svc.Runtime.ActivePaths()
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(active.SourceTokenPath(keyID))
			if err != nil {
				t.Fatal(err)
			}
			leave(svc)
			if _, svcErr := svc.SetSourceToken(keyID, "screening", []byte("other")); svcErr == nil || svcErr.Kind != ErrorLocked {
				t.Fatalf("SetSourceToken(%s) error = %#v", name, svcErr)
			}
			if _, svcErr := svc.RemoveSourceToken(keyID, "screening"); svcErr == nil || svcErr.Kind != ErrorLocked {
				t.Fatalf("RemoveSourceToken(%s) error = %#v", name, svcErr)
			}
			if after, err := os.ReadFile(active.SourceTokenPath(keyID)); err != nil || string(after) != string(before) {
				t.Fatalf("a refused change wrote the token file: %v", err)
			}
		})
	}
}

func TestRemoveSourceTokenDeletesTheLastTokensFile(t *testing.T) {
	svc, keyID := cosignerWithKey(t)
	for _, source := range []string{"ops", "screening"} {
		if _, svcErr := svc.SetSourceToken(keyID, source, []byte(source+"-token")); svcErr != nil {
			t.Fatal(svcErr)
		}
	}
	listing, svcErr := svc.RemoveSourceToken(keyID, "ops")
	if svcErr != nil || len(listing) != 1 || listing[0].Source != "screening" {
		t.Fatalf("RemoveSourceToken(one of two) = %+v, %#v", listing, svcErr)
	}
	if _, ok := svc.Runtime.SourceTokenFor(keyID, "ops"); ok {
		t.Fatal("a removed token is still published")
	}
	if _, svcErr := svc.RemoveSourceToken(keyID, "ops"); svcErr == nil || svcErr.Kind != ErrorSourceTokenNotSet {
		t.Fatalf("RemoveSourceToken(again) error = %#v, want no token set", svcErr)
	}
	// On the wire it is its own code, not a missing key.
	if got := ipcCodeForErrorKind(&Error{Kind: ErrorSourceTokenNotSet}); got != protocol.ErrCodeSourceTokenNotSet {
		t.Fatalf("wire code = %q, want %q", got, protocol.ErrCodeSourceTokenNotSet)
	}
	listing, svcErr = svc.RemoveSourceToken(keyID, "screening")
	if svcErr != nil || len(listing) != 0 {
		t.Fatalf("RemoveSourceToken(last) = %+v, %#v", listing, svcErr)
	}
	active, err := svc.Runtime.ActivePaths()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(active.SourceTokenPath(keyID)); !os.IsNotExist(err) {
		t.Fatalf("the file survived the removal of its last token: %v", err)
	}
	// Removal never archives.
	if entries, err := os.ReadDir(active.DeletedSourceTokensDir()); err != nil || len(entries) != 0 {
		t.Fatalf("deleted source tokens after a removal = %v, %v", entries, err)
	}
	if _, ok := svc.Runtime.SourceTokenFor(keyID, "screening"); ok {
		t.Fatal("the last removed token is still published")
	}
	if _, svcErr := svc.RemoveSourceToken(unheldWitnessKeyID, "screening"); svcErr == nil || svcErr.Kind != ErrorSourceTokenNotSet {
		t.Fatalf("RemoveSourceToken(no file) error = %#v, want no token set", svcErr)
	}
}

// A write whose directory sync fails after the rename has put the new file
// in place: the change is reported as failed, and the index follows the file,
// as a key reload follows a key write.
func TestSetSourceTokenWithUncertainDurabilityPublishesWhatTheFileHolds(t *testing.T) {
	svc, keyID := cosignerWithKey(t)
	if _, svcErr := svc.SetSourceToken(keyID, "screening", []byte("old-token")); svcErr != nil {
		t.Fatal(svcErr)
	}
	active, err := svc.Runtime.ActivePaths()
	if err != nil {
		t.Fatal(err)
	}
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpDirSync && path == active.SourceTokensDir() {
			return errors.New("injected directory sync failure")
		}
		return nil
	}
	_, svcErr := svc.SetSourceToken(keyID, "screening", []byte("new-token"))
	fsutil.TestHook = nil
	if svcErr == nil || svcErr.Kind != ErrorInternal || !strings.Contains(svcErr.Message, "directory sync failed") {
		t.Fatalf("SetSourceToken(sync fails) error = %#v, want a durability failure", svcErr)
	}
	if strings.Contains(svcErr.Message, "new-token") {
		t.Fatalf("the error quotes the token: %s", svcErr.Message)
	}
	if got, ok := svc.Runtime.SourceTokenFor(keyID, "screening"); !ok || got != "new-token" {
		t.Fatalf("SourceTokenFor() = %q, %v; want the token the file now holds", got, ok)
	}
}

// Deleting a cosigner key archives its token file with it.
func TestDeleteKeyArchivesTheKeysSourceTokens(t *testing.T) {
	svc, keyID := cosignerWithKey(t)
	if _, svcErr := svc.SetSourceToken(keyID, "screening", []byte("token")); svcErr != nil {
		t.Fatal(svcErr)
	}
	if _, svcErr := svc.DeleteKey(context.Background(), keyID); svcErr != nil {
		t.Fatalf("DeleteKey() error = %#v", svcErr)
	}
	active, err := svc.Runtime.ActivePaths()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(active.SourceTokenPath(keyID)); !os.IsNotExist(err) {
		t.Fatalf("the deleted key's token file is still active: %v", err)
	}
	if _, err := os.Stat(active.DeletedSourceTokenPath(keyID)); err != nil {
		t.Fatalf("the deleted key's token file was not archived: %v", err)
	}
	if _, svcErr := svc.SetSourceToken(keyID, "screening", []byte("token")); svcErr == nil || svcErr.Kind != ErrorNotFound {
		t.Fatalf("SetSourceToken(deleted key) error = %#v, want not found", svcErr)
	}
}
