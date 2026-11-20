// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/appinput"
	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/cmdspec"
)

// commonAppCallOptions are the options both forms of app call parse.
type commonAppCallOptions struct {
	apshellapp.AppCallOptions
	// seen holds the single-valued options given so far, the app call
	// forms' own (from, abi) included, so a repeat is refused.
	seen cmdspec.SeenOptions
}

func newCommonAppCallOptions() commonAppCallOptions {
	return commonAppCallOptions{
		AppCallOptions: apshellapp.AppCallOptions{Wait: true, OnCompletion: types.NoOpOC},
		seen:           cmdspec.SeenOptions{},
	}
}

// appProgramOption is one spelling of a program option: which program it
// sets, and how its value says whether the file is compiled.
type appProgramOption struct {
	kind   string
	source func(value string) appinput.ProgramSource
}

func programAs(compiled bool) func(string) appinput.ProgramSource {
	return func(value string) appinput.ProgramSource {
		return appinput.ProgramSource{Path: value, Compiled: compiled}
	}
}

var appProgramOptions = map[string]appProgramOption{
	"approval":      {"approval", appinput.DetectProgramSource},
	"approval-teal": {"approval", programAs(false)},
	"approval-bin":  {"approval", programAs(true)},
	"clear":         {"clear", appinput.DetectProgramSource},
	"clear-teal":    {"clear", programAs(false)},
	"clear-bin":     {"clear", programAs(true)},
}

// applyAppTxnOption applies name=value when name is a program, note or fee
// option, which app call and app deploy share, and reports whether it was
// one. Each is single-valued.
func applyAppTxnOption(opts *apshellapp.AppTxnOptions, seen cmdspec.SeenOptions, name, value string) (bool, error) {
	if option, known := appProgramOptions[name]; known {
		return true, setAppProgram(opts, seen, option.kind, option.source(value))
	}
	if name != "note" && name != "fee" {
		return false, nil
	}
	if err := seen.Once(name); err != nil {
		return true, err
	}
	if name == "note" {
		opts.Note = value
		return true, nil
	}
	fee, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return true, fmt.Errorf("invalid fee value: %s", value)
	}
	opts.Fee = fee
	opts.UseFlatFee = true
	return true, nil
}

// setAppProgram records the approval or clear program, once.
func setAppProgram(opts *apshellapp.AppTxnOptions, seen cmdspec.SeenOptions, kind string, source appinput.ProgramSource) error {
	if source.Path == "" {
		return fmt.Errorf("missing value for %s", kind)
	}
	if err := seen.Once(kind); err != nil {
		return err
	}
	if kind == "approval" {
		opts.ApprovalPath, opts.ApprovalCompiled = source.Path, source.Compiled
	} else {
		opts.ClearPath, opts.ClearCompiled = source.Path, source.Compiled
	}
	return nil
}

func parseCommonAppCallOption(args []string, i int, opts *commonAppCallOptions) (int, bool, error) {
	arg := args[i]
	if name, value, ok := strings.Cut(arg, "="); ok {
		if handled, err := applyAppTxnOption(&opts.AppTxnOptions, opts.seen, name, value); handled {
			return i, true, err
		}
	}

	switch {
	case arg == "nowait":
		opts.Wait = false
		return i, true, nil
	case arg == "--pay":
		i++
		if i >= len(args) {
			return i, true, fmt.Errorf("missing value for --pay")
		}
		// --pay and pay= are one option.
		if err := opts.seen.Once("pay"); err != nil {
			return i, true, err
		}
		payAmount, err := strconv.ParseUint(args[i], 10, 64)
		if err != nil {
			return i, true, fmt.Errorf("invalid --pay value: %s", args[i])
		}
		opts.PayAmount = payAmount
		return i, true, nil
	case strings.HasPrefix(arg, "pay="):
		if err := opts.seen.Once("pay"); err != nil {
			return i, true, err
		}
		payAmount, err := strconv.ParseUint(strings.TrimPrefix(arg, "pay="), 10, 64)
		if err != nil {
			return i, true, fmt.Errorf("invalid pay value: %s", strings.TrimPrefix(arg, "pay="))
		}
		opts.PayAmount = payAmount
		return i, true, nil
	case strings.HasPrefix(arg, "account="):
		opts.Accounts = append(opts.Accounts, strings.TrimPrefix(arg, "account="))
		return i, true, nil
	case strings.HasPrefix(arg, "app="):
		ref, err := parseAppID(strings.TrimPrefix(arg, "app="))
		if err != nil {
			return i, true, err
		}
		// The list is sent as typed, so a zero is refused here, where the
		// argument can be named, and not dropped.
		if ref == 0 {
			return i, true, fmt.Errorf("invalid %s: a foreign app ID must be non-zero", arg)
		}
		// Kept exactly as typed, in order: a program reads these by position.
		opts.ForeignApps = append(opts.ForeignApps, ref)
		return i, true, nil
	case strings.HasPrefix(arg, "asset="):
		ref, err := cmdspec.ParseAssetRef(strings.TrimPrefix(arg, "asset="))
		if err != nil {
			return i, true, fmt.Errorf("invalid asset reference: %w", err)
		}
		opts.AssetRefs = append(opts.AssetRefs, ref)
		return i, true, nil
	case strings.HasPrefix(arg, "box="):
		boxRef, err := parseBoxRef(strings.TrimPrefix(arg, "box="))
		if err != nil {
			return i, true, err
		}
		opts.Boxes = append(opts.Boxes, boxRef)
		return i, true, nil
	case strings.HasPrefix(arg, "oncomp="):
		if err := opts.seen.Once("oncomp"); err != nil {
			return i, true, err
		}
		onComp, err := appinput.ParseOnCompletion(strings.TrimPrefix(arg, "oncomp="))
		if err != nil {
			return i, true, err
		}
		opts.OnCompletion = onComp
		return i, true, nil
	case strings.HasPrefix(arg, "arg:"):
		return i, true, cmdspec.AddLsigArg(&opts.LsigArgs, arg)
	default:
		return i, false, nil
	}
}

func parseRawAppCallArgs(args []string) (*apshellapp.AppCallRawRequest, error) {
	common := newCommonAppCallOptions()
	params := &apshellapp.AppCallRawRequest{}

	if len(args) < 4 || args[0] != "raw" {
		return nil, fmt.Errorf("usage: app call raw <app-id> from <account> [arg-raw=<bytes> ...] [--pay <microalgos>] [account=<account> ...] [app=<app-id> ...] [asset=<asset> ...] [box=<name>|<app-id>:<name> ...] [oncomp=<noop|optin|closeout|clear|update|delete>] [approval=<path>|approval-teal=<path>|approval-bin=<path>] [clear=<path>|clear-teal=<path>|clear-bin=<path>] [note=<text>] [fee=<microalgos>] [nowait] [arg:[<account>:]<name>=<value>]")
	}

	appID, err := parseAppID(args[1])
	if err != nil {
		return nil, err
	}
	params.AppID = appID

	if args[2] != "from" || args[3] == "" {
		return nil, fmt.Errorf("usage: app call raw <app-id> from <account>")
	}
	params.From = args[3]

	for i := 4; i < len(args); i++ {
		arg := args[i]
		switch {
		case strings.HasPrefix(arg, "arg-raw="):
			value, err := appinput.ParseByteValue(strings.TrimPrefix(arg, "arg-raw="))
			if err != nil {
				return nil, fmt.Errorf("invalid arg-raw value: %w", err)
			}
			params.AppArgs = append(params.AppArgs, value)
		default:
			nextIdx, handled, err := parseCommonAppCallOption(args, i, &common)
			if err != nil {
				return nil, err
			}
			if !handled {
				return nil, fmt.Errorf("unknown app call argument: %s", arg)
			}
			i = nextIdx
		}
	}

	params.AppCallOptions = common.AppCallOptions
	return params, nil
}

func parseMethodAppCallArgs(args []string) (*apshellapp.AppCallMethodRequest, error) {
	common := newCommonAppCallOptions()
	params := &apshellapp.AppCallMethodRequest{}

	if len(args) < 2 {
		return nil, fmt.Errorf("usage: app call <app-id> <method> --abi <path> from <account> [--arg <value> ...] [--pay <microalgos>] [account=<account> ...] [app=<app-id> ...] [asset=<asset> ...] [box=<name>|<app-id>:<name> ...] [oncomp=<noop|optin|closeout|clear|update|delete>] [approval=<path>|approval-teal=<path>|approval-bin=<path>] [clear=<path>|clear-teal=<path>|clear-bin=<path>] [note=<text>] [fee=<microalgos>] [nowait] [arg:[<account>:]<name>=<value>]")
	}

	appID, err := parseAppID(args[0])
	if err != nil {
		return nil, err
	}
	params.AppID = appID
	params.Method = args[1]

	for i := 2; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--abi":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("missing value for --abi")
			}
			// --abi and abi= are one option.
			if err := common.seen.Once("abi"); err != nil {
				return nil, err
			}
			params.ABIPath = args[i]
		case strings.HasPrefix(arg, "abi="):
			if err := common.seen.Once("abi"); err != nil {
				return nil, err
			}
			params.ABIPath = strings.TrimPrefix(arg, "abi=")
		case arg == "from":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("usage: app call %d %s --abi <path> from <account>", params.AppID, params.Method)
			}
			if err := common.seen.Once("from"); err != nil {
				return nil, err
			}
			params.From = args[i]
		case arg == "--arg":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("missing value for --arg")
			}
			params.ArgValues = append(params.ArgValues, args[i])
		case strings.HasPrefix(arg, "arg="):
			params.ArgValues = append(params.ArgValues, strings.TrimPrefix(arg, "arg="))
		default:
			nextIdx, handled, err := parseCommonAppCallOption(args, i, &common)
			if err != nil {
				return nil, err
			}
			if !handled {
				return nil, fmt.Errorf("unknown app call argument: %s", arg)
			}
			i = nextIdx
		}
	}

	params.AppCallOptions = common.AppCallOptions

	if params.ABIPath == "" {
		return nil, fmt.Errorf("app call requires --abi <path>")
	}
	if params.From == "" {
		return nil, fmt.Errorf("app call requires from <account>")
	}
	return params, nil
}

func parseAppID(raw string) (uint64, error) {
	appID, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid app ID: %s", raw)
	}
	return appID, nil
}

func parseBoxName(raw string) ([]byte, error) {
	name, err := appinput.ParseByteValue(raw)
	if err != nil {
		return nil, err
	}
	if len(name) == 0 {
		return nil, fmt.Errorf("box name must be non-empty")
	}
	return name, nil
}

// parseBoxRef reads `<name>` or `<app-id>:<name>`. A box written without an
// app ID belongs to the called app and carries app ID 0, which always encodes
// as index 0: the same bytes whether or not the called app is also listed
// with `app=`. Naming an app ID, the called app's included, asks for that
// app's position in the list.
func parseBoxRef(raw string) (types.AppBoxReference, error) {
	appID := uint64(0)
	nameRaw := raw

	if idx := strings.Index(raw, ":"); idx > 0 {
		if parsed, err := strconv.ParseUint(raw[:idx], 10, 64); err == nil {
			appID = parsed
			nameRaw = raw[idx+1:]
		}
	}

	name, err := parseBoxName(nameRaw)
	if err != nil {
		return types.AppBoxReference{}, err
	}

	return types.AppBoxReference{
		AppID: appID,
		Name:  name,
	}, nil
}
