// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyadmin

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/policyruntime"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	"github.com/aplane-algo/aplane/internal/sourcetokens"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// SetSourceToken sets token as source's token for a cosigner policy
// selector: a cosigner key the node holds, or "default" for the node default
// document. It replaces any token source had. The token is copied; the
// caller zeroes its own buffer.
//
// The change is an in-place write of the selected generation's
// source_tokens/<selector>.enc, as key generation and deletion are: no
// generation is minted. It runs under the store mutation lock on an unlocked
// cosigner node, and the token index is published once the write is
// durable. The result lists the selector's tokens without their values.
func (s Service) SetSourceToken(selector, source string, token []byte) ([]sourcetokens.Entry, *Error) {
	setAt := time.Now()
	return s.changeSourceTokens(selector, true, func(current *sourcetokens.File) (*sourcetokens.File, error) {
		return sourcetokens.SetToken(current, selector, source, token, setAt)
	})
}

// RemoveSourceToken removes source's token from a cosigner policy selector.
// Removing the selector's last token deletes its file: nothing is archived,
// so the deleted archive never keeps a removed token. Generations minted
// while the token was set keep their copy until they are pruned, and backups
// made while it was set keep theirs.
func (s Service) RemoveSourceToken(selector, source string) ([]sourcetokens.Entry, *Error) {
	return s.changeSourceTokens(selector, false, func(current *sourcetokens.File) (*sourcetokens.File, error) {
		return sourcetokens.RemoveToken(current, source)
	})
}

// MaxListedSourceTokenSelectors bounds a listing of every selector. One
// selector's listing holds at most eight tokens and eight sources, a few
// kilobytes, so this many fit one admin frame with room to spare. A listing
// of one selector is always whole.
const MaxListedSourceTokenSelectors = 512

// ListSourceTokens lists a cosigner node's tokens by source name and set
// time, never by value.
//
// With a selector it lists that one, and then "default" when the selector is
// a key that follows the node default, whose tokens serve its checks. Without
// one it lists every selector with a token or with a source that needs one,
// "default" first and then the keys in order, at most
// MaxListedSourceTokenSelectors of them, and returns how many it left out.
// after, which only a listing of every selector takes, pages it: the listing
// starts with the first selector that comes after it in that order, so a
// caller that passes the last selector of each page reads every selector.
//
// A selector's tokens serve the policy document keyed by it: a token is in
// use when a source of that document takes a token by its name, and unused
// otherwise; a source that takes a token the selector lacks is listed as
// needed. It reads the token files of the selected generation under the store
// mutation lock, beside the policy the runtime published from that
// generation, and zeroes every token it decrypts.
func (s Service) ListSourceTokens(selector, after string) ([]adminproto.SourceTokenSelector, int, *Error) {
	ir := s.Runtime
	if ir == nil {
		return nil, 0, &Error{Kind: ErrorInternal, Message: "product runtime is nil"}
	}
	if ir.NodeRole() != noderole.RoleCosigner {
		return nil, 0, &Error{Kind: ErrorInvalidInput, Message: "source tokens are kept only on a cosigner node"}
	}
	if selector != "" {
		if err := sourcetokens.ValidateSelector(selector); err != nil {
			return nil, 0, &Error{Kind: ErrorInvalidInput, Message: err.Error()}
		}
	}
	if after != "" {
		if selector != "" {
			return nil, 0, &Error{Kind: ErrorInvalidInput, Message: "after pages a listing of every selector; list one selector without it"}
		}
		if err := sourcetokens.ValidateSelector(after); err != nil {
			return nil, 0, &Error{Kind: ErrorInvalidInput, Message: "after: " + err.Error()}
		}
	}
	unlockMutation, lockErr := s.lockUnlockedMutation()
	if lockErr != nil {
		return nil, 0, lockErr
	}
	defer unlockMutation()
	np := ir.NodePolicy()
	if np == nil {
		return nil, 0, &Error{Kind: ErrorLocked, Message: "policy is not loaded; unlock the signer"}
	}
	var wanted []string
	if selector != "" {
		wanted = []string{selector}
		if selector != sourcetokens.DefaultSelector && !np.HasOwn(selector) {
			if _, err := ir.FindKeyFile(selector); err != nil {
				return nil, 0, &Error{Kind: ErrorNotFound, Message: "the node holds no cosigner key " + selector}
			}
			wanted = append(wanted, sourcetokens.DefaultSelector)
		}
	}
	active, err := ir.ActivePaths()
	if err != nil {
		return nil, 0, mapGenerateError(err)
	}
	var listings map[string][]sourcetokens.Entry
	omitted := 0
	err = ir.WithKeyring(func(kr *crypto.Keyring) error {
		read := wanted
		if wanted == nil {
			var pageErr error
			if wanted, read, omitted, pageErr = sourceTokenPage(np, active, after); pageErr != nil || len(read) == 0 {
				return pageErr
			}
		}
		var readErr error
		listings, readErr = sourcetokens.Listings(active, kr, read...)
		return readErr
	})
	if err != nil {
		return nil, 0, sourceTokenError(selector, err)
	}
	out := make([]adminproto.SourceTokenSelector, 0, len(wanted))
	for _, listed := range wanted {
		out = append(out, sourceTokenListing(np, listed, listings[listed]))
	}
	return out, omitted, nil
}

// sourceTokenPage chooses the page of a listing of every selector that starts
// after after, before anything is decrypted: a selector is listed when it has
// a token file, which always holds a token, or when its document has a source
// that takes one. read is the page's selectors with a token file, the only
// files the listing reads.
func sourceTokenPage(np *policyruntime.NodePolicy, active storepaths.GenPaths, after string) (page, read []string, omitted int, err error) {
	withFiles, err := sourcetokens.Selectors(active)
	if err != nil {
		return nil, nil, 0, err
	}
	hasFile := make(map[string]bool, len(withFiles))
	for _, s := range withFiles {
		hasFile[s] = true
	}
	listed := func(s string) bool { return hasFile[s] || takesAToken(np, s) }
	page, omitted = pageSourceTokenSelectors(listingOrder(np, withFiles), listed, after, MaxListedSourceTokenSelectors)
	for _, s := range page {
		if hasFile[s] {
			read = append(read, s)
		}
	}
	return page, read, omitted, nil
}

// listingOrder is every selector a listing of all might report, in its
// order: "default" first, then those with a token file and those with a
// document of their own, sorted.
func listingOrder(np *policyruntime.NodePolicy, withFiles []string) []string {
	seen := map[string]bool{}
	for _, selector := range withFiles {
		seen[selector] = true
	}
	for selector := range np.Keys {
		seen[selector] = true
	}
	delete(seen, sourcetokens.DefaultSelector)
	return append([]string{sourcetokens.DefaultSelector}, slices.Sorted(maps.Keys(seen))...)
}

// pageSourceTokenSelectors is one page of order: the first limit selectors
// that come after after (in order's order, "default" first; "" starts at the
// beginning) and that listed reports, with how many such selectors follow
// the page. after need not be in order.
func pageSourceTokenSelectors(order []string, listed func(string) bool, after string, limit int) ([]string, int) {
	comesAfter := func(selector string) bool {
		switch {
		case after == "":
			return true
		case after == sourcetokens.DefaultSelector:
			return selector != sourcetokens.DefaultSelector
		case selector == sourcetokens.DefaultSelector:
			return false
		}
		return selector > after
	}
	var page []string
	omitted := 0
	for _, selector := range order {
		if !comesAfter(selector) || !listed(selector) {
			continue
		}
		if len(page) < limit {
			page = append(page, selector)
			continue
		}
		omitted++
	}
	return page, omitted
}

// takesAToken reports whether a source of the document selector's tokens
// serve takes a token: the node default for "default", the key's own
// document otherwise, and none for a key that follows the node default.
func takesAToken(np *policyruntime.NodePolicy, selector string) bool {
	doc := np.Keys[selector]
	if selector == sourcetokens.DefaultSelector {
		doc = np.Default
	}
	if doc == nil {
		return false
	}
	for _, source := range doc.ExternalSources {
		if source.Token != nil {
			return true
		}
	}
	return false
}

// sourceTokenListing reports selector's tokens against the document keyed by
// it: the node default for "default", the key's own document otherwise, and
// none for a key that follows the node default.
func sourceTokenListing(np *policyruntime.NodePolicy, selector string, entries []sourcetokens.Entry) adminproto.SourceTokenSelector {
	var doc *policy.Config
	if selector == sourcetokens.DefaultSelector {
		doc = np.Default
	} else {
		doc = np.Keys[selector]
	}
	listing := adminproto.SourceTokenSelector{Selector: selector, Policy: adminproto.SourceTokenPolicyDefault}
	if doc != nil || selector == sourcetokens.DefaultSelector {
		listing.Policy = adminproto.SourceTokenPolicyOwn
	}
	var sources map[string]policy.ExternalSourceV1
	if doc != nil {
		sources = doc.ExternalSources
	}
	listing.Sources = slices.Sorted(maps.Keys(sources))
	listing.Tokens = sourceTokenRows(sources, entries)
	return listing
}

// sourceTokenRows is each token set, in use when a source takes a token by
// its name and unused otherwise, and each source that takes a token none
// is set for, needed; sorted by source name.
func sourceTokenRows(sources map[string]policy.ExternalSourceV1, entries []sourcetokens.Entry) []adminproto.SourceTokenInfo {
	rows := make([]adminproto.SourceTokenInfo, 0, len(entries)+len(sources))
	set := make(map[string]bool, len(entries))
	for _, entry := range entries {
		set[entry.Source] = true
		state := adminproto.SourceTokenUnused
		if source, ok := sources[entry.Source]; ok && source.Token != nil {
			state = adminproto.SourceTokenInUse
		}
		rows = append(rows, adminproto.SourceTokenInfo{Source: entry.Source, SetAt: entry.SetAt, State: state})
	}
	for name, source := range sources {
		if source.Token != nil && !set[name] {
			rows = append(rows, adminproto.SourceTokenInfo{Source: name, State: adminproto.SourceTokenNeeded})
		}
	}
	slices.SortFunc(rows, func(a, b adminproto.SourceTokenInfo) int { return strings.Compare(a.Source, b.Source) })
	return rows
}

// sourceTokenChange is a pure change of one selector's token file: nil in,
// for a selector without one, and nil out, to delete it.
type sourceTokenChange func(current *sourcetokens.File) (*sourcetokens.File, error)

// sourceTokenRefusal is the change itself refused (a token or name outside
// the rules, a token past the cap, a source with no token to remove), as
// opposed to a failure to read or write the store.
type sourceTokenRefusal struct{ err error }

func (r sourceTokenRefusal) Error() string { return r.err.Error() }
func (r sourceTokenRefusal) Unwrap() error { return r.err }

func (s Service) changeSourceTokens(selector string, requireHeld bool, change sourceTokenChange) ([]sourcetokens.Entry, *Error) {
	ir := s.Runtime
	if ir == nil {
		return nil, &Error{Kind: ErrorInternal, Message: "product runtime is nil"}
	}
	if ir.NodeRole() != noderole.RoleCosigner {
		return nil, &Error{Kind: ErrorInvalidInput, Message: "source tokens are kept only on a cosigner node"}
	}
	if err := sourcetokens.ValidateSelector(selector); err != nil {
		return nil, &Error{Kind: ErrorInvalidInput, Message: err.Error()}
	}
	unlockMutation, lockErr := s.lockUnlockedMutation()
	if lockErr != nil {
		return nil, lockErr
	}
	defer unlockMutation()
	// The session the write begins in: the index is published only in it.
	generation, unlocked := ir.UnlockedGeneration()
	if !unlocked {
		return nil, &Error{Kind: ErrorLocked, Message: "signer is not unlocked"}
	}
	if requireHeld && selector != sourcetokens.DefaultSelector {
		if _, err := ir.FindKeyFile(selector); err != nil {
			return nil, &Error{Kind: ErrorNotFound, Message: "the node holds no cosigner key " + selector}
		}
	}
	active, err := ir.ActivePaths()
	if err != nil {
		return nil, mapGenerateError(err)
	}

	var next *sourcetokens.File
	defer func() { next.Zero() }()
	var writeErr error
	err = ir.WithKeyring(func(kr *crypto.Keyring) error {
		current, _, err := sourcetokens.ReadFile(active, selector, kr)
		if err != nil {
			return err
		}
		defer current.Zero()
		if next, err = change(current); err != nil {
			return sourceTokenRefusal{err}
		}
		if next == nil {
			writeErr = sourcetokens.RemoveFile(active, selector)
		} else {
			writeErr = sourcetokens.WriteFile(active, next, kr)
		}
		if writeErr != nil {
			// The file may or may not have changed (a directory sync that
			// failed after the rename leaves the new file in place). Publish
			// what it now holds, as a key watcher reload would for a key
			// write, so the runtime never serves a token the file does not.
			republishSourceTokensFromDisk(ir, generation, active, selector, kr)
		}
		return nil
	})
	if err != nil {
		return nil, sourceTokenError(selector, err)
	}
	if writeErr != nil {
		return nil, sourceTokenError(selector, writeErr)
	}
	ir.ReplaceSourceTokens(generation, selector, next)
	return next.Listing(), nil
}

// republishSourceTokensFromDisk publishes selector's tokens as its file holds
// them after a failed write, or none when the file cannot be read: a lookup
// then refuses rather than send a token the store may not keep.
func republishSourceTokensFromDisk(ir *productruntime.Runtime, generation uint64, active storepaths.GenPaths, selector string, kr *crypto.Keyring) {
	onDisk, _, err := sourcetokens.ReadFile(active, selector, kr)
	if err != nil {
		onDisk = nil
	}
	defer onDisk.Zero()
	ir.ReplaceSourceTokens(generation, selector, onDisk)
}

// sourceTokenError classifies a failed token change. No error here carries a
// token value: the sourcetokens package never puts one in an error.
func sourceTokenError(selector string, err error) *Error {
	var refusal sourceTokenRefusal
	switch {
	case isLockedStateError(err):
		return &Error{Kind: ErrorLocked, Message: "signer is locked"}
	case errors.As(err, &refusal) && errors.Is(err, sourcetokens.ErrTokenNotSet):
		return &Error{Kind: ErrorNotFound, Message: err.Error()}
	case errors.As(err, &refusal), errors.Is(err, sourcetokens.ErrFileTooLarge):
		return &Error{Kind: ErrorInvalidInput, Message: err.Error()}
	default:
		return &Error{Kind: ErrorInternal, Message: fmt.Sprintf("changing the source tokens of %s failed: %v", selector, err)}
	}
}

// SetSourceToken sets a source token for an admin session. The request's
// token is copied; the adapter zeroes its own buffer.
func (s IPCService) SetSourceToken(req adminproto.SetSourceTokenRequest) adminproto.SourceTokenChangeResult {
	entries, err := s.Service.SetSourceToken(req.Selector, req.Source, req.Token)
	return s.Service.sourceTokenChangeResult(req.Selector, req.Source, entries, err)
}

// RemoveSourceToken removes a source token for an admin session.
func (s IPCService) RemoveSourceToken(req adminproto.RemoveSourceTokenRequest) adminproto.SourceTokenChangeResult {
	entries, err := s.Service.RemoveSourceToken(req.Selector, req.Source)
	return s.Service.sourceTokenChangeResult(req.Selector, req.Source, entries, err)
}

// ListSourceTokens lists source tokens by name for an admin session.
func (s IPCService) ListSourceTokens(req adminproto.ListSourceTokensRequest) adminproto.ListSourceTokensResult {
	selectors, omitted, err := s.Service.ListSourceTokens(req.Selector, req.After)
	if err != nil {
		return adminproto.ListSourceTokensResult{Code: ipcCodeForErrorKind(err), Error: err.Message}
	}
	return adminproto.ListSourceTokensResult{Success: true, Selectors: selectors, Omitted: omitted}
}

// sourceTokenChangeResult reports a change with the selector's tokens after
// it, each with its state against the policy the runtime now holds.
func (s Service) sourceTokenChangeResult(selector, source string, entries []sourcetokens.Entry, err *Error) adminproto.SourceTokenChangeResult {
	if err != nil {
		return adminproto.SourceTokenChangeResult{Selector: selector, Source: source, Code: ipcCodeForErrorKind(err), Error: err.Message}
	}
	np := s.Runtime.NodePolicy()
	if np == nil {
		np = &policyruntime.NodePolicy{}
	}
	return adminproto.SourceTokenChangeResult{
		Success: true, Selector: selector, Source: source,
		Tokens: sourceTokenListing(np, selector, entries).Tokens,
	}
}
