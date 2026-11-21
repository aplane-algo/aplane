// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyadmin

import (
	"errors"
	"fmt"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	"github.com/aplane-algo/aplane/internal/signerapp/sourcetokens"
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
// while the token was set keep their copy until they are pruned.
func (s Service) RemoveSourceToken(selector, source string) ([]sourcetokens.Entry, *Error) {
	return s.changeSourceTokens(selector, false, func(current *sourcetokens.File) (*sourcetokens.File, error) {
		return sourcetokens.RemoveToken(current, source)
	})
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
