// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/appinput"
	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/cmdspec"
)

type rawAppCallArgs struct {
	AppID            uint64
	From             string
	AppArgs          [][]byte
	PayAmount        uint64
	Accounts         []string
	ForeignApps      []uint64
	AssetRefs        []cmdspec.AssetRef
	Boxes            []types.AppBoxReference
	OnCompletion     types.OnCompletion
	ApprovalPath     string
	ApprovalCompiled bool
	ClearPath        string
	ClearCompiled    bool
	Note             string
	Wait             bool
	Fee              uint64
	UseFlatFee       bool
	LsigArgs         map[string][]byte
}

type methodAppCallArgs struct {
	AppID            uint64
	Method           string
	ABIPath          string
	ArgValues        []string
	PayAmount        uint64
	From             string
	Accounts         []string
	ForeignApps      []uint64
	AssetRefs        []cmdspec.AssetRef
	Boxes            []types.AppBoxReference
	OnCompletion     types.OnCompletion
	ApprovalPath     string
	ApprovalCompiled bool
	ClearPath        string
	ClearCompiled    bool
	Note             string
	Wait             bool
	Fee              uint64
	UseFlatFee       bool
	LsigArgs         map[string][]byte
}

type commonAppCallOptions struct {
	Wait             bool
	PayAmount        uint64
	Accounts         []string
	ForeignApps      []uint64
	AssetRefs        []cmdspec.AssetRef
	Boxes            []types.AppBoxReference
	OnCompletion     types.OnCompletion
	ApprovalPath     string
	ApprovalCompiled bool
	ClearPath        string
	ClearCompiled    bool
	Note             string
	Fee              uint64
	UseFlatFee       bool
	LsigArgs         map[string][]byte
}

func newCommonAppCallOptions() commonAppCallOptions {
	return commonAppCallOptions{
		Wait:         true,
		OnCompletion: types.NoOpOC,
	}
}

func parseCommonAppCallOption(args []string, i int, appID uint64, opts *commonAppCallOptions) (int, bool, error) {
	arg := args[i]

	setProgram := func(kind, value string, compiled bool) error {
		if value == "" {
			return fmt.Errorf("missing value for %s", kind)
		}
		switch kind {
		case "approval":
			opts.ApprovalPath = value
			opts.ApprovalCompiled = compiled
		case "clear":
			opts.ClearPath = value
			opts.ClearCompiled = compiled
		default:
			return fmt.Errorf("unknown program kind: %s", kind)
		}
		return nil
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
		payAmount, err := strconv.ParseUint(args[i], 10, 64)
		if err != nil {
			return i, true, fmt.Errorf("invalid --pay value: %s", args[i])
		}
		opts.PayAmount = payAmount
		return i, true, nil
	case strings.HasPrefix(arg, "pay="):
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
		if ref != appID && !slices.Contains(opts.ForeignApps, ref) {
			opts.ForeignApps = append(opts.ForeignApps, ref)
		}
		return i, true, nil
	case strings.HasPrefix(arg, "asset="):
		ref, err := cmdspec.ParseAssetRef(strings.TrimPrefix(arg, "asset="))
		if err != nil {
			return i, true, fmt.Errorf("invalid asset reference: %w", err)
		}
		opts.AssetRefs = append(opts.AssetRefs, ref)
		return i, true, nil
	case strings.HasPrefix(arg, "box="):
		boxRef, err := parseBoxRef(strings.TrimPrefix(arg, "box="), appID)
		if err != nil {
			return i, true, err
		}
		opts.Boxes = append(opts.Boxes, boxRef)
		return i, true, nil
	case strings.HasPrefix(arg, "oncomp="):
		onComp, err := appinput.ParseOnCompletion(strings.TrimPrefix(arg, "oncomp="))
		if err != nil {
			return i, true, err
		}
		opts.OnCompletion = onComp
		return i, true, nil
	case strings.HasPrefix(arg, "approval-teal="):
		return i, true, setProgram("approval", strings.TrimPrefix(arg, "approval-teal="), false)
	case strings.HasPrefix(arg, "approval-bin="):
		return i, true, setProgram("approval", strings.TrimPrefix(arg, "approval-bin="), true)
	case strings.HasPrefix(arg, "approval="):
		src := appinput.DetectProgramSource(strings.TrimPrefix(arg, "approval="))
		return i, true, setProgram("approval", src.Path, src.Compiled)
	case strings.HasPrefix(arg, "clear-teal="):
		return i, true, setProgram("clear", strings.TrimPrefix(arg, "clear-teal="), false)
	case strings.HasPrefix(arg, "clear-bin="):
		return i, true, setProgram("clear", strings.TrimPrefix(arg, "clear-bin="), true)
	case strings.HasPrefix(arg, "clear="):
		src := appinput.DetectProgramSource(strings.TrimPrefix(arg, "clear="))
		return i, true, setProgram("clear", src.Path, src.Compiled)
	case strings.HasPrefix(arg, "note="):
		opts.Note = strings.TrimPrefix(arg, "note=")
		return i, true, nil
	case strings.HasPrefix(arg, "fee="):
		feeVal, err := strconv.ParseUint(strings.TrimPrefix(arg, "fee="), 10, 64)
		if err != nil {
			return i, true, fmt.Errorf("invalid fee value: %s", strings.TrimPrefix(arg, "fee="))
		}
		opts.Fee = feeVal
		opts.UseFlatFee = true
		return i, true, nil
	case strings.HasPrefix(arg, "arg:"):
		argName, value, err := cmdspec.ParseLsigArg(arg)
		if err != nil {
			return i, true, err
		}
		if opts.LsigArgs == nil {
			opts.LsigArgs = make(map[string][]byte)
		}
		opts.LsigArgs[argName] = value
		return i, true, nil
	default:
		return i, false, nil
	}
}

func parseRawAppCallArgs(args []string) (*rawAppCallArgs, error) {
	common := newCommonAppCallOptions()
	params := &rawAppCallArgs{
		Wait:         common.Wait,
		OnCompletion: common.OnCompletion,
	}

	if len(args) < 4 || args[0] != "raw" {
		return nil, fmt.Errorf("usage: app call raw <app-id> from <account> [arg-raw=<bytes> ...] [--pay <microalgos>] [account=<account> ...] [app=<app-id> ...] [asset=<asset> ...] [box=<name>|<app-id>:<name> ...] [oncomp=<noop|optin|closeout|clear|update|delete>] [approval=<path>|approval-teal=<path>|approval-bin=<path>] [clear=<path>|clear-teal=<path>|clear-bin=<path>] [note=<text>] [fee=<microalgos>] [nowait] [arg:name=value]")
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
			nextIdx, handled, err := parseCommonAppCallOption(args, i, params.AppID, &common)
			if err != nil {
				return nil, err
			}
			if !handled {
				return nil, fmt.Errorf("unknown app call argument: %s", arg)
			}
			i = nextIdx
		}
	}

	params.Wait = common.Wait
	params.PayAmount = common.PayAmount
	params.Accounts = common.Accounts
	params.ForeignApps = common.ForeignApps
	params.AssetRefs = common.AssetRefs
	params.Boxes = common.Boxes
	params.OnCompletion = common.OnCompletion
	params.ApprovalPath = common.ApprovalPath
	params.ApprovalCompiled = common.ApprovalCompiled
	params.ClearPath = common.ClearPath
	params.ClearCompiled = common.ClearCompiled
	params.Note = common.Note
	params.Fee = common.Fee
	params.UseFlatFee = common.UseFlatFee
	params.LsigArgs = common.LsigArgs

	if params.OnCompletion == types.UpdateApplicationOC {
		if params.ApprovalPath == "" {
			return nil, fmt.Errorf("app update requires approval=<path> or approval-bin=<path>")
		}
		if params.ClearPath == "" {
			return nil, fmt.Errorf("app update requires clear=<path> or clear-bin=<path>")
		}
	} else if params.ApprovalPath != "" || params.ClearPath != "" {
		return nil, fmt.Errorf("approval and clear programs are only valid with oncomp=update")
	}

	return params, nil
}

func (a *rawAppCallArgs) toAppRawRequest() apshellapp.AppCallRawRequest {
	return apshellapp.AppCallRawRequest{
		AppID:            a.AppID,
		From:             a.From,
		AppArgs:          a.AppArgs,
		PayAmount:        a.PayAmount,
		Accounts:         a.Accounts,
		ForeignApps:      a.ForeignApps,
		AssetRefs:        a.AssetRefs,
		Boxes:            a.Boxes,
		OnCompletion:     a.OnCompletion,
		ApprovalPath:     a.ApprovalPath,
		ApprovalCompiled: a.ApprovalCompiled,
		ClearPath:        a.ClearPath,
		ClearCompiled:    a.ClearCompiled,
		Note:             a.Note,
		Wait:             a.Wait,
		Fee:              a.Fee,
		UseFlatFee:       a.UseFlatFee,
		LsigArgs:         a.LsigArgs,
	}
}

func parseMethodAppCallArgs(args []string) (*methodAppCallArgs, error) {
	common := newCommonAppCallOptions()
	params := &methodAppCallArgs{
		Wait:         common.Wait,
		OnCompletion: common.OnCompletion,
	}

	if len(args) < 2 {
		return nil, fmt.Errorf("usage: app call <app-id> <method> --abi <path> from <account> [--arg <value> ...] [--pay <microalgos>] [account=<account> ...] [app=<app-id> ...] [asset=<asset> ...] [box=<name>|<app-id>:<name> ...] [oncomp=<noop|optin|closeout|clear|update|delete>] [approval=<path>|approval-teal=<path>|approval-bin=<path>] [clear=<path>|clear-teal=<path>|clear-bin=<path>] [note=<text>] [fee=<microalgos>] [nowait] [arg:name=value]")
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
			params.ABIPath = args[i]
		case strings.HasPrefix(arg, "abi="):
			params.ABIPath = strings.TrimPrefix(arg, "abi=")
		case arg == "from":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("usage: app call %d %s --abi <path> from <account>", params.AppID, params.Method)
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
			nextIdx, handled, err := parseCommonAppCallOption(args, i, params.AppID, &common)
			if err != nil {
				return nil, err
			}
			if !handled {
				return nil, fmt.Errorf("unknown app call argument: %s", arg)
			}
			i = nextIdx
		}
	}

	params.Wait = common.Wait
	params.PayAmount = common.PayAmount
	params.Accounts = common.Accounts
	params.ForeignApps = common.ForeignApps
	params.AssetRefs = common.AssetRefs
	params.Boxes = common.Boxes
	params.OnCompletion = common.OnCompletion
	params.ApprovalPath = common.ApprovalPath
	params.ApprovalCompiled = common.ApprovalCompiled
	params.ClearPath = common.ClearPath
	params.ClearCompiled = common.ClearCompiled
	params.Note = common.Note
	params.Fee = common.Fee
	params.UseFlatFee = common.UseFlatFee
	params.LsigArgs = common.LsigArgs

	if params.ABIPath == "" {
		return nil, fmt.Errorf("app call requires --abi <path>")
	}
	if params.From == "" {
		return nil, fmt.Errorf("app call requires from <account>")
	}
	if params.OnCompletion == types.UpdateApplicationOC {
		if params.ApprovalPath == "" {
			return nil, fmt.Errorf("app update requires approval=<path> or approval-bin=<path>")
		}
		if params.ClearPath == "" {
			return nil, fmt.Errorf("app update requires clear=<path> or clear-bin=<path>")
		}
	} else if params.ApprovalPath != "" || params.ClearPath != "" {
		return nil, fmt.Errorf("approval and clear programs are only valid with oncomp=update")
	}

	return params, nil
}

func (a *methodAppCallArgs) toAppMethodRequest() apshellapp.AppCallMethodRequest {
	return apshellapp.AppCallMethodRequest{
		AppID:            a.AppID,
		Method:           a.Method,
		ABIPath:          a.ABIPath,
		ArgValues:        a.ArgValues,
		PayAmount:        a.PayAmount,
		From:             a.From,
		Accounts:         a.Accounts,
		ForeignApps:      a.ForeignApps,
		AssetRefs:        a.AssetRefs,
		Boxes:            a.Boxes,
		OnCompletion:     a.OnCompletion,
		ApprovalPath:     a.ApprovalPath,
		ApprovalCompiled: a.ApprovalCompiled,
		ClearPath:        a.ClearPath,
		ClearCompiled:    a.ClearCompiled,
		Note:             a.Note,
		Wait:             a.Wait,
		Fee:              a.Fee,
		UseFlatFee:       a.UseFlatFee,
		LsigArgs:         a.LsigArgs,
	}
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

func parseBoxRef(raw string, curAppID uint64) (types.AppBoxReference, error) {
	appID := curAppID
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
