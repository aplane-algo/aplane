// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package shellrepl

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aplane-algo/aplane/internal/cmdspec"
)

// TransactionParams holds parsed parameters for send command
type TransactionParams struct {
	Amount     cmdspec.AmountText
	Asset      cmdspec.AssetRef // "algo" or ASA name/ID
	FromRaw    []string         // Raw sender inputs (aliases, addresses, @setnames)
	ToRaw      []string         // Raw receiver inputs (aliases, addresses, @setnames)
	Note       string
	Wait       bool
	Atomic     bool              // true if atomic group transaction
	Fee        uint64            // transaction fee in microAlgos
	UseFlatFee bool              // true if user explicitly set fee (even if zero)
	LsigArgs   map[string][]byte // LogicSig arguments for generic LogicSigs (e.g., HTLC preimage)
}

// OptInParams holds parsed parameters for optin command
type OptInParams struct {
	ASARef     cmdspec.AssetRef // ASA name or ID
	From       string           // Account to opt-in
	Wait       bool
	Fee        uint64            // transaction fee in microAlgos
	UseFlatFee bool              // true if user explicitly set fee (even if zero)
	LsigArgs   map[string][]byte // LogicSig arguments for generic LogicSigs
}

// RekeyParams holds parsed parameters for rekey command
type RekeyParams struct {
	Account    string // Account to rekey
	Signer     string // New signing authority
	Wait       bool
	Fee        uint64            // transaction fee in microAlgos
	UseFlatFee bool              // true if user explicitly set fee (even if zero)
	LsigArgs   map[string][]byte // LogicSig arguments for generic LogicSigs
}

// OptOutParams holds parsed parameters for optout command
type OptOutParams struct {
	ASARef     cmdspec.AssetRef // ASA name or ID
	Account    string           // Account to opt out
	CloseTo    string           // Where to send remaining balance (optional)
	Wait       bool
	Fee        uint64            // transaction fee in microAlgos
	UseFlatFee bool              // true if user explicitly set fee (even if zero)
	LsigArgs   map[string][]byte // LogicSig arguments for generic LogicSigs
}

// CloseParams holds parsed parameters for close command
type CloseParams struct {
	Account    string // Account to close
	CloseTo    string // Where to send remaining balance
	Wait       bool
	Fee        uint64            // transaction fee in microAlgos
	UseFlatFee bool              // true if user explicitly set fee (even if zero)
	LsigArgs   map[string][]byte // LogicSig arguments for generic LogicSigs
}

// KeyRegParams holds parsed parameters for keyreg command
type KeyRegParams struct {
	From              string
	Mode              string // "online" or "offline" (for compatibility)
	Online            bool
	VoteKey           string
	SelKey            string
	SProofKey         string
	VoteFirst         uint64
	VoteLast          uint64
	KeyDilution       uint64
	IncentiveEligible bool
	Wait              bool
	LsigArgs          map[string][]byte
}

// ParseSendCommand parses natural language send syntax:
// send <amount> <asset> from <sender(s)> to <receiver(s)> [note=<text>] [fee=<microalgos>] [nowait] [atomic]
// Supports inline sets: send 1 algo from a1 a2 a3 to bob
func ParseSendCommand(args []string) (TransactionParams, error) {
	params := TransactionParams{
		Wait:       true,  // Default wait for confirmation
		Fee:        0,     // Default fee (network suggested)
		UseFlatFee: false, // Default to network suggested fee
	}

	if len(args) < 5 {
		return params, fmt.Errorf("usage: send <amount> <asset> from <sender(s)> to <receiver(s)> [note=<text>] [fee=<microalgos>] [nowait] [atomic]\nExample: send 2.1 algo from alice to bob\nExample: send 1 algo from alice to @friends atomic\nExample: send 1 algo from a1 a2 a3 to bob atomic")
	}

	// Position 0: amount
	var err error
	params.Amount, err = cmdspec.ParseAmountText(args[0])
	if err != nil {
		return params, fmt.Errorf("invalid amount: %w", err)
	}

	// Position 1: asset (algo, usdc, or ASA ID)
	params.Asset, err = cmdspec.ParseAssetRef(args[1])
	if err != nil {
		return params, fmt.Errorf("invalid asset: %w", err)
	}

	if !strings.EqualFold(args[2], "from") {
		return params, fmt.Errorf("missing 'from' keyword\nUsage: send <amount> <asset> from <sender> to <receiver>")
	}

	var nextIdx int
	params.FromRaw, nextIdx, err = parseAddressSpan(args, 3)
	if err != nil {
		return params, fmt.Errorf("failed to parse sender set: %w", err)
	}
	if len(params.FromRaw) == 0 {
		return params, fmt.Errorf("missing sender after 'from'")
	}
	if nextIdx >= len(args) || !strings.EqualFold(args[nextIdx], "to") {
		return params, fmt.Errorf("missing 'to' keyword\nUsage: send <amount> <asset> from <sender> to <receiver>")
	}

	params.ToRaw, nextIdx, err = parseAddressSpan(args, nextIdx+1)
	if err != nil {
		return params, fmt.Errorf("failed to parse receiver set: %w", err)
	}
	if len(params.ToRaw) == 0 {
		return params, fmt.Errorf("missing receiver after 'to'")
	}

	if err := parseSendTrailingArgs(args[nextIdx:], &params); err != nil {
		return params, err
	}

	return params, nil
}

// ParseOptinCommand parses natural language optin syntax:
// optin <asset> for <account> [fee=<microalgos>] [nowait] [arg:name=value]
func ParseOptinCommand(args []string) (OptInParams, error) {
	params := OptInParams{
		Wait:       true,
		Fee:        0,
		UseFlatFee: false,
	}

	if len(args) < 3 {
		return params, fmt.Errorf("usage: optin <asset> for <account> [fee=<microalgos>] [nowait]\nExample: optin usdc for alice")
	}

	// Position 0: asset
	var err error
	params.ASARef, err = cmdspec.ParseAssetRef(args[0])
	if err != nil {
		return params, fmt.Errorf("invalid asset: %w", err)
	}

	if !strings.EqualFold(args[1], "for") {
		return params, fmt.Errorf("missing 'for' keyword\nUsage: optin <asset> for <account>")
	}

	// Extract account (token after "for")
	if len(args) < 3 {
		return params, fmt.Errorf("missing account after 'for'")
	}
	params.From = args[2]

	// Parse optional flags
	if err := parseWaitFeeLsigTrailingArgs(args[3:], &params.Wait, &params.Fee, &params.UseFlatFee, &params.LsigArgs); err != nil {
		return params, err
	}

	return params, nil
}

// ParseOptoutCommand parses natural language optout syntax:
// optout <asset> from <account> [to <dest>] [fee=<microalgos>] [nowait] [arg:name=value]
func ParseOptoutCommand(args []string) (OptOutParams, error) {
	params := OptOutParams{
		Wait:       true,
		Fee:        0,
		UseFlatFee: false,
	}

	if len(args) < 3 {
		return params, fmt.Errorf("usage: optout <asset> from <account> [to <dest>] [fee=<microalgos>] [nowait]\nExample: optout usdc from alice")
	}

	// Position 0: asset
	var err error
	params.ASARef, err = cmdspec.ParseAssetRef(args[0])
	if err != nil {
		return params, fmt.Errorf("invalid asset: %w", err)
	}

	if !strings.EqualFold(args[1], "from") {
		return params, fmt.Errorf("missing 'from' keyword\nUsage: optout <asset> from <account>")
	}

	// Extract account (token after "from")
	if len(args) < 3 {
		return params, fmt.Errorf("missing account after 'from'")
	}
	params.Account = args[2]

	nextIdx := 3
	if nextIdx < len(args) && strings.EqualFold(args[nextIdx], "to") {
		if nextIdx+1 >= len(args) {
			return params, fmt.Errorf("missing close-to address after 'to'")
		}
		nextArg := args[nextIdx+1]
		if !isTrailingFlagLike(nextArg) {
			params.CloseTo = nextArg
			nextIdx += 2
		} else {
			nextIdx++
		}
	}

	// Parse optional flags
	if err := parseWaitFeeLsigTrailingArgs(args[nextIdx:], &params.Wait, &params.Fee, &params.UseFlatFee, &params.LsigArgs); err != nil {
		return params, err
	}

	return params, nil
}

// ParseCloseCommand parses natural language close syntax:
// close <account> to <destination> [fee=<microalgos>] [nowait] [arg:name=value]
func ParseCloseCommand(args []string) (CloseParams, error) {
	params := CloseParams{
		Wait:       true,
		Fee:        0,
		UseFlatFee: false,
	}

	if len(args) < 3 {
		return params, fmt.Errorf("usage: close <account> to <destination> [fee=<microalgos>] [nowait] [arg:name=value]\nExample: close alice to bob")
	}

	// Position 0: account to close
	params.Account = args[0]

	if !strings.EqualFold(args[1], "to") {
		return params, fmt.Errorf("missing 'to' keyword\nUsage: close <account> to <destination>")
	}

	// Extract destination (token after "to")
	if len(args) < 3 {
		return params, fmt.Errorf("missing destination after 'to'")
	}
	params.CloseTo = args[2]

	if err := parseWaitFeeLsigTrailingArgs(args[3:], &params.Wait, &params.Fee, &params.UseFlatFee, &params.LsigArgs); err != nil {
		return params, err
	}

	return params, nil
}

// ParseRekeyCommand parses natural language rekey syntax:
// rekey <account> to <signer> [fee=<microalgos>] [nowait] [arg:name=value]
// Also handles unrekey: unrekey <account> [fee=<microalgos>] [nowait] [arg:name=value]
func ParseRekeyCommand(args []string, isUnrekey bool) (RekeyParams, error) {
	params := RekeyParams{
		Wait:       true,
		Fee:        0,
		UseFlatFee: false,
	}
	for _, arg := range args {
		if strings.EqualFold(arg, "using") {
			return params, fmt.Errorf("external contract-admin keys are handled by aprekey rekey/unrekey")
		}
	}

	if isUnrekey {
		// unrekey <account> [fee=<microalgos>] [nowait] [arg:name=value]
		if len(args) < 1 {
			return params, fmt.Errorf("usage: unrekey <account> [fee=<microalgos>] [nowait] [arg:name=value]\nExample: unrekey alice")
		}
		params.Account = args[0]
		params.Signer = args[0] // Rekey to self

		// Parse optional flags
		if err := parseWaitFeeLsigTrailingArgs(args[1:], &params.Wait, &params.Fee, &params.UseFlatFee, &params.LsigArgs); err != nil {
			return params, err
		}
		return params, nil
	}

	// rekey <account> to <signer> [nowait]
	if len(args) < 3 {
		return params, fmt.Errorf("usage: rekey <account> to <signer> [nowait]\nExample: rekey alice to bob")
	}

	// Position 0: account
	params.Account = args[0]

	if !strings.EqualFold(args[1], "to") {
		return params, fmt.Errorf("missing 'to' keyword\nUsage: rekey <account> to <signer>")
	}

	// Extract signer (token after "to")
	if len(args) < 3 {
		return params, fmt.Errorf("missing signer after 'to'")
	}
	params.Signer = args[2]

	if err := parseWaitFeeLsigTrailingArgs(args[3:], &params.Wait, &params.Fee, &params.UseFlatFee, &params.LsigArgs); err != nil {
		return params, err
	}

	return params, nil
}

// ParseTakeCommand parses natural language keyreg syntax:
// keyreg <account> <online|offline> [votekey=...] [selkey=...] [sproofkey=...] [votefirst=...] [votelast=...] [keydilution=...] [eligible=true] [nowait] [arg:name=value]
func ParseTakeCommand(args []string) (KeyRegParams, error) {
	params := KeyRegParams{
		Wait:              true,
		IncentiveEligible: false, // Default to NOT eligible (requires explicit flag)
		VoteFirst:         0,
		VoteLast:          3000000,
		KeyDilution:       10000,
	}

	if len(args) < 2 {
		return params, fmt.Errorf("usage: keyreg <account> <online|offline> [votekey=...] [selkey=...] [sproofkey=...] [votefirst=...] [votelast=...] [keydilution=...] [eligible=true] [nowait]\nExample: keyreg alice online votekey=ABC selkey=DEF sproofkey=GHI votefirst=1000 votelast=2000 keydilution=10000 eligible=true")
	}

	// Position 0: account
	params.From = args[0]

	// Position 1: online/offline
	switch strings.ToLower(args[1]) {
	case "online":
		params.Online = true
		params.Mode = "online"
	case "offline":
		params.Online = false
		params.Mode = "offline"
	default:
		return params, fmt.Errorf("second argument must be 'online' or 'offline', got: %s", args[1])
	}

	// Parse optional key=value pairs and flags
	for i := 2; i < len(args); i++ {
		arg := args[i]
		if arg == "nowait" {
			params.Wait = false
		} else if strings.HasPrefix(arg, "arg:") {
			argName, argValue, err := cmdspec.ParseLsigArg(arg)
			if err != nil {
				return params, err
			}
			if params.LsigArgs == nil {
				params.LsigArgs = make(map[string][]byte)
			}
			params.LsigArgs[argName] = argValue
		} else if strings.Contains(arg, "=") {
			parts := strings.SplitN(arg, "=", 2)
			if len(parts) != 2 {
				return params, fmt.Errorf("invalid argument format: %s", arg)
			}
			key := parts[0]
			value := parts[1]

			switch key {
			case "votekey":
				params.VoteKey = value
			case "selkey":
				params.SelKey = value
			case "sproofkey":
				params.SProofKey = value
			case "votefirst":
				val, err := parseUint64(value)
				if err != nil {
					return params, fmt.Errorf("invalid votefirst value: %s", value)
				}
				params.VoteFirst = val
			case "votelast":
				val, err := parseUint64(value)
				if err != nil {
					return params, fmt.Errorf("invalid votelast value: %s", value)
				}
				params.VoteLast = val
			case "keydilution":
				val, err := parseUint64(value)
				if err != nil {
					return params, fmt.Errorf("invalid keydilution value: %s", value)
				}
				params.KeyDilution = val
			case "eligible":
				params.IncentiveEligible = value == "true" || value == "1"
			default:
				return params, fmt.Errorf("unknown argument: %s", key)
			}
		}
	}

	// Validate: if going online, must have required keys
	if params.Online && (params.VoteKey == "" || params.SelKey == "" || params.SProofKey == "") {
		return params, fmt.Errorf("going online requires votekey=..., selkey=..., and sproofkey=... parameters")
	}

	return params, nil
}

func parseUint64(s string) (uint64, error) {
	result, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid uint64: %s", s)
	}
	return result, nil
}

func parseWaitFeeLsigTrailingArgs(args []string, wait *bool, fee *uint64, useFlatFee *bool, lsigArgs *map[string][]byte) error {
	for _, arg := range args {
		if strings.EqualFold(arg, "nowait") {
			*wait = false
		} else if strings.HasPrefix(arg, "fee=") {
			feeStr := strings.TrimPrefix(arg, "fee=")
			feeVal, err := parseUint64(feeStr)
			if err != nil {
				return fmt.Errorf("invalid fee value: %s", feeStr)
			}
			*fee = feeVal
			*useFlatFee = true
		} else if strings.HasPrefix(arg, "arg:") && lsigArgs != nil {
			argName, argValue, err := cmdspec.ParseLsigArg(arg)
			if err != nil {
				return err
			}
			if *lsigArgs == nil {
				*lsigArgs = make(map[string][]byte)
			}
			(*lsigArgs)[argName] = argValue
		}
	}
	return nil
}

func isTrailingFlagLike(arg string) bool {
	return strings.EqualFold(arg, "nowait") || strings.Contains(arg, "=")
}

// SweepParams holds parsed parameters for sweep command
type SweepParams struct {
	Asset      cmdspec.AssetRef   // "algo" or ASA name/ID
	FromRaw    []string           // Raw source inputs (aliases, addresses, @setnames) - nil means all signable
	ToRaw      string             // Raw destination input (alias, address)
	Leaving    cmdspec.AmountText // Amount to leave in each source (optional)
	Wait       bool
	Fee        uint64            // transaction fee in microAlgos
	UseFlatFee bool              // true if user explicitly set fee (even if zero)
	LsigArgs   map[string][]byte // LogicSig arguments applied to each generated transaction
}

// ParseSweepCommand parses sweep syntax:
// sweep <asset> from [account1 account2 ...] to <dest> [leaving <amount>] [fee=<microalgos>] [nowait]
// sweep <asset> to <dest> [leaving <amount>] [fee=<microalgos>] [nowait]  (uses all signable accounts)
func ParseSweepCommand(args []string) (SweepParams, error) {
	params := SweepParams{
		Wait:       true,
		Fee:        0,
		UseFlatFee: false,
		Leaving:    cmdspec.AmountText("0"), // Default: sweep everything
		FromRaw:    nil,                     // nil = use all signable accounts
		ToRaw:      "",
	}

	if len(args) < 3 {
		return params, fmt.Errorf("usage: sweep <asset> [from [account1 account2 ...] | from @setname] to <dest> [leaving <amount>] [fee=<microalgos>] [nowait]\n" +
			"Examples:\n" +
			"  sweep usdc from [alice bob charlie] to treasury\n" +
			"  sweep usdc from @team to treasury\n" +
			"  sweep algo from [alice bob] to main leaving 1\n" +
			"  sweep algo to main leaving 1  (sweeps from all signable accounts)")
	}

	// Position 0: asset (algo, usdc, or ASA ID)
	var err error
	params.Asset, err = cmdspec.ParseAssetRef(args[0])
	if err != nil {
		return params, fmt.Errorf("invalid asset: %w", err)
	}

	nextIdx := 1
	switch {
	case strings.EqualFold(args[nextIdx], "from"):
		var err error
		params.FromRaw, nextIdx, err = parseAddressSpan(args, nextIdx+1)
		if err != nil {
			return params, fmt.Errorf("failed to parse account set: %w", err)
		}
		if len(params.FromRaw) == 0 {
			return params, fmt.Errorf("no accounts specified in set")
		}
		if nextIdx >= len(args) || !strings.EqualFold(args[nextIdx], "to") {
			return params, fmt.Errorf("missing 'to' keyword after account set")
		}
		nextIdx++
	case strings.EqualFold(args[nextIdx], "to"):
		nextIdx++
	default:
		return params, fmt.Errorf("missing 'to' keyword")
	}

	if nextIdx >= len(args) {
		return params, fmt.Errorf("missing destination after 'to'")
	}
	params.ToRaw = args[nextIdx]
	nextIdx++

	if err := parseSweepTrailingArgs(args[nextIdx:], &params); err != nil {
		return params, err
	}

	return params, nil
}

func parseAddressSpan(args []string, startIdx int) ([]string, int, error) {
	if startIdx >= len(args) {
		return nil, startIdx, fmt.Errorf("missing address")
	}
	if strings.HasPrefix(args[startIdx], "[") {
		items, endIdx, err := cmdspec.ExtractBracketList(args, startIdx)
		if err != nil {
			return nil, startIdx, err
		}
		return items, endIdx + 1, nil
	}
	return []string{args[startIdx]}, startIdx + 1, nil
}

func parseSendTrailingArgs(args []string, params *TransactionParams) error {
	seenFee := false
	for i := 0; i < len(args); i++ {
		switch {
		case strings.EqualFold(args[i], "nowait"):
			params.Wait = false
		case strings.EqualFold(args[i], "atomic"):
			params.Atomic = true
		case strings.HasPrefix(args[i], "note="):
			params.Note = strings.TrimPrefix(args[i], "note=")
		case strings.EqualFold(args[i], "note"):
			i++
			if i >= len(args) {
				return fmt.Errorf("missing note value")
			}
			params.Note = args[i]
		case strings.HasPrefix(args[i], "fee="):
			if seenFee {
				return fmt.Errorf("duplicate fee flag")
			}
			feeStr := strings.TrimPrefix(args[i], "fee=")
			feeVal, err := parseUint64(feeStr)
			if err != nil {
				return fmt.Errorf("invalid fee value: %s", feeStr)
			}
			params.Fee = feeVal
			params.UseFlatFee = true
			seenFee = true
		case strings.HasPrefix(args[i], "arg:"):
			argName, argValue, err := cmdspec.ParseLsigArg(args[i])
			if err != nil {
				return err
			}
			if params.LsigArgs == nil {
				params.LsigArgs = make(map[string][]byte)
			}
			params.LsigArgs[argName] = argValue
		}
	}
	return nil
}

func parseSweepTrailingArgs(args []string, params *SweepParams) error {
	for i := 0; i < len(args); i++ {
		switch {
		case strings.EqualFold(args[i], "leaving"):
			i++
			if i >= len(args) {
				return fmt.Errorf("missing amount after 'leaving'")
			}
			amount, err := cmdspec.ParseAmountText(args[i])
			if err != nil {
				return fmt.Errorf("invalid leaving amount: %w", err)
			}
			params.Leaving = amount
		case strings.EqualFold(args[i], "nowait"):
			params.Wait = false
		case strings.HasPrefix(args[i], "fee="):
			feeStr := strings.TrimPrefix(args[i], "fee=")
			feeVal, err := parseUint64(feeStr)
			if err != nil {
				return fmt.Errorf("invalid fee value: %s", feeStr)
			}
			params.Fee = feeVal
			params.UseFlatFee = true
		case strings.HasPrefix(args[i], "arg:"):
			argName, argValue, err := cmdspec.ParseLsigArg(args[i])
			if err != nil {
				return err
			}
			if params.LsigArgs == nil {
				params.LsigArgs = make(map[string][]byte)
			}
			params.LsigArgs[argName] = argValue
		}
	}
	return nil
}

// findKeyword returns the index of a keyword in args, or -1 if not found
func findKeyword(args []string, keyword string) int {
	for i, arg := range args {
		if strings.ToLower(arg) == keyword {
			return i
		}
	}
	return -1
}
