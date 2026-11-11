// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"errors"
	"strconv"
	"strings"

	"github.com/aplane-algo/aplane/internal/engine"
)

// The engine refuses LogicSig argument names that no signing key declares
// with an *engine.UndeclaredLsigArgsError. The functions below word that
// refusal in the terms the arguments were given in; any other error is
// returned as it is.

// ShellLsigArgsError words the refusal for the shell: the names as the arg:
// tokens that were typed, and the command that reloads the key list.
func ShellLsigArgsError(err error) error {
	return undeclaredLsigArgsError(err, func(names []string) string {
		tokens := make([]string, len(names))
		for i, name := range names {
			tokens[i] = "arg:" + name
		}
		return strings.Join(tokens, ", ")
	}, "no transaction here is signed by a key that declares this LogicSig argument, so it would not be sent; check the name, or run keys refresh if the key is new")
}

// scriptLsigArgsError words the refusal for a script: the names as keys of the
// lsigArgs option it passed.
func scriptLsigArgsError(err error) error {
	return undeclaredLsigArgsError(err, func(names []string) string {
		quoted := make([]string, len(names))
		for i, name := range names {
			quoted[i] = strconv.Quote(name)
		}
		return "lsigArgs " + strings.Join(quoted, ", ")
	}, "no account here is signed by a key that declares this LogicSig argument, so it would not be sent; check the name")
}

// undeclaredLsigArgsError words the refusal as the names, as given, then why.
// When some accounts' keys could not be looked up, why says so, and that a
// retry may find a key that declares the names.
func undeclaredLsigArgsError(err error, given func(names []string) string, declaredByNone string) error {
	var undeclared *engine.UndeclaredLsigArgsError
	if !errors.As(err, &undeclared) {
		return err
	}
	why := declaredByNone
	if undeclared.Unresolved > 0 {
		why = "none of the keys that could be looked up declares this LogicSig argument, so it would not be sent; " +
			engine.UnresolvedAccounts(undeclared.Unresolved) + ", and a retry may differ; check the name"
	}
	return &wordedError{text: given(undeclared.Names) + ": " + why, err: undeclared}
}

// wordedError is an engine error given in a caller's own terms. It still
// unwraps to the engine error.
type wordedError struct {
	text string
	err  error
}

func (e *wordedError) Error() string { return e.text }
func (e *wordedError) Unwrap() error { return e.err }
