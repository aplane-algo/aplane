// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
)

// The engine refuses LogicSig argument names that no signing key declares
// with an *engine.UndeclaredLsigArgsError. The functions below word that
// refusal in the terms the arguments were given in; any other error is
// returned as it is.

// ShellLsigArgsError words the refusal for the shell: the names as the arg:
// tokens that were typed, and the command that reloads the key list.
func ShellLsigArgsError(err error) error {
	return undeclaredLsigArgsError(err, shellArgTokens,
		"no transaction here is signed by a key that declares this LogicSig argument, so it would not be sent; check the name, or run keys refresh if the key is new")
}

// shellArgTokens writes LogicSig argument names as the arg: tokens typed.
func shellArgTokens(names []string) string {
	tokens := make([]string, len(names))
	for i, name := range names {
		tokens[i] = "arg:" + name
	}
	return strings.Join(tokens, ", ")
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

// CheckPluginLsigArgs refuses, before the user is asked to review a plugin's
// group, the arg: names the group would not send: a name no position APlane
// signs declares, and any name for a pregrouped-signed group, of which APlane
// signs nothing. SubmitPluginTransactions checks the same again when it
// signs. What this check cannot settle here, a group that does not decode or
// a signer that is not connected, is left to the submission, which refuses
// it; a failed key lookup refuses a name here only as it does there.
func (a *App) CheckPluginLsigArgs(ctx context.Context, result *jsonrpc.ExecuteResult, lsigArgs map[string][]byte) error {
	if len(lsigArgs) == 0 || result == nil || len(result.Transactions) == 0 {
		return nil
	}
	var pluginOwned map[string]string
	switch result.GroupMode {
	case "":
	case jsonrpc.GroupModePresignPlan:
		pluginOwned = make(map[string]string, len(result.PluginSigners))
		for _, signer := range result.PluginSigners {
			pluginOwned[signer.Address] = signer.SignerRef
		}
	case jsonrpc.GroupModePregroupedSigned:
		return pregroupedSignedLsigArgsError()
	default:
		return nil
	}
	if !a.eng.IsConnected() {
		return nil
	}
	txns, err := engine.ProcessTransactionIntents(result.Transactions)
	if err != nil {
		return nil
	}
	_, err = a.eng.LsigArgsByDeclaredName(ctx, pluginSlotSenders(txns, pluginOwned), lsigArgs)
	var undeclared *engine.UndeclaredLsigArgsError
	if errors.As(err, &undeclared) {
		return err
	}
	return nil
}

// pregroupedSignedLsigArgsError refuses LogicSig arguments for a
// pregrouped-signed group: the plugin signed every transaction, so APlane
// has none to give them to.
func pregroupedSignedLsigArgsError() error {
	return fmt.Errorf("groupMode %q does not allow lsig args", jsonrpc.GroupModePregroupedSigned)
}

// PluginLsigArgsNotSentError reports the arg: values of a plugin command none
// of whose steps returned transactions for APlane to sign: they were sent
// nowhere, which is said rather than passed over. It is nil when none were
// given.
func PluginLsigArgsNotSentError(lsigArgs map[string][]byte) error {
	if len(lsigArgs) == 0 {
		return nil
	}
	names := make([]string, 0, len(lsigArgs))
	for name := range lsigArgs {
		names = append(names, name)
	}
	sort.Strings(names)
	pronoun := "it was"
	if len(names) > 1 {
		pronoun = "they were"
	}
	return fmt.Errorf("%s: the plugin returned no transactions for APlane to sign, so %s not sent", shellArgTokens(names), pronoun)
}
