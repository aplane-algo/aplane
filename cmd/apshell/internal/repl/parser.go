// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package repl

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// TransactionParams holds parsed parameters for send command
type TransactionParams struct {
	Amount     string
	Asset      string   // "algo" or ASA name/ID
	FromRaw    []string // Raw sender inputs (aliases, addresses, @setnames)
	ToRaw      []string // Raw receiver inputs (aliases, addresses, @setnames)
	Note       string
	Wait       bool
	Atomic     bool              // true if atomic group transaction
	Fee        uint64            // transaction fee in microAlgos
	UseFlatFee bool              // true if user explicitly set fee (even if zero)
	LsigArgs   map[string][]byte // LogicSig arguments for generic LogicSigs (e.g., hashlock preimage)
}

// OptInParams holds parsed parameters for optin command
type OptInParams struct {
	ASARef     string // ASA name or ID
	From       string // Account to opt-in
	Wait       bool
	Fee        uint64 // transaction fee in microAlgos
	UseFlatFee bool   // true if user explicitly set fee (even if zero)
}

// RekeyParams holds parsed parameters for rekey command
type RekeyParams struct {
	Account    string // Account to rekey
	Signer     string // New signing authority
	Wait       bool
	Fee        uint64 // transaction fee in microAlgos
	UseFlatFee bool   // true if user explicitly set fee (even if zero)
}

// OptOutParams holds parsed parameters for optout command
type OptOutParams struct {
	ASARef     string // ASA name or ID
	Account    string // Account to opt out
	CloseTo    string // Where to send remaining balance (optional)
	Wait       bool
	Fee        uint64 // transaction fee in microAlgos
	UseFlatFee bool   // true if user explicitly set fee (even if zero)
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
	params.Amount = args[0]

	// Position 1: asset (algo, usdc, or ASA ID)
	params.Asset = args[1]

	// Find keyword positions
	fromIdx := findKeyword(args, "from")
	toIdx := findKeyword(args, "to")

	if fromIdx == -1 {
		return params, fmt.Errorf("missing 'from' keyword\nUsage: send <amount> <asset> from <sender> to <receiver>")
	}
	if toIdx == -1 {
		return params, fmt.Errorf("missing 'to' keyword\nUsage: send <amount> <asset> from <sender> to <receiver>")
	}

	// Extract senders after "from"
	// Syntax: single address OR bracketed set [addr1 addr2 ...]
	if fromIdx+1 >= len(args) {
		return params, fmt.Errorf("missing sender after 'from'")
	}
	firstSenderToken := args[fromIdx+1]
	if strings.HasPrefix(firstSenderToken, "[") {
		// Bracketed set: collect until we find closing bracket
		if strings.HasSuffix(firstSenderToken, "]") {
			// Single token like [addr] - strip brackets
			addr := strings.TrimPrefix(strings.TrimSuffix(firstSenderToken, "]"), "[")
			if addr != "" {
				params.FromRaw = append(params.FromRaw, addr)
			}
		} else {
			// Multi-token: [addr1 addr2 ... ]
			first := strings.TrimPrefix(firstSenderToken, "[")
			if first != "" {
				params.FromRaw = append(params.FromRaw, first)
			}
			// Collect until closing bracket (but not past "to")
			for i := fromIdx + 2; i < toIdx; i++ {
				arg := args[i]
				if strings.HasSuffix(arg, "]") {
					last := strings.TrimSuffix(arg, "]")
					if last != "" {
						params.FromRaw = append(params.FromRaw, last)
					}
					break
				}
				params.FromRaw = append(params.FromRaw, arg)
			}
		}
	} else {
		// Single address (no brackets)
		params.FromRaw = append(params.FromRaw, firstSenderToken)
	}
	if len(params.FromRaw) == 0 {
		return params, fmt.Errorf("missing sender after 'from'")
	}

	// Extract receivers after "to"
	// Syntax: single address OR bracketed set [addr1 addr2 ...]
	if toIdx+1 >= len(args) {
		return params, fmt.Errorf("missing receiver after 'to'")
	}
	firstReceiverToken := args[toIdx+1]
	if strings.HasPrefix(firstReceiverToken, "[") {
		// Bracketed set: collect until we find closing bracket
		// Handle [addr] (single token) or [addr1 addr2 ...] (multiple tokens)
		if strings.HasSuffix(firstReceiverToken, "]") {
			// Single token like [addr] - strip brackets
			addr := strings.TrimPrefix(strings.TrimSuffix(firstReceiverToken, "]"), "[")
			if addr != "" {
				params.ToRaw = append(params.ToRaw, addr)
			}
		} else {
			// Multi-token: [addr1 addr2 ... ]
			// First token without leading bracket
			first := strings.TrimPrefix(firstReceiverToken, "[")
			if first != "" {
				params.ToRaw = append(params.ToRaw, first)
			}
			// Collect until closing bracket
			for i := toIdx + 2; i < len(args); i++ {
				arg := args[i]
				if strings.HasSuffix(arg, "]") {
					// Last token - strip trailing bracket
					last := strings.TrimSuffix(arg, "]")
					if last != "" {
						params.ToRaw = append(params.ToRaw, last)
					}
					break
				}
				params.ToRaw = append(params.ToRaw, arg)
			}
		}
	} else {
		// Single address (no brackets)
		params.ToRaw = append(params.ToRaw, firstReceiverToken)
	}
	if len(params.ToRaw) == 0 {
		return params, fmt.Errorf("missing receiver after 'to'")
	}

	// Parse optional flags
	for i := 0; i < len(args); i++ {
		if args[i] == "nowait" {
			params.Wait = false
		} else if args[i] == "atomic" {
			params.Atomic = true
		} else if strings.HasPrefix(args[i], "note=") {
			// Support note=value syntax
			params.Note = strings.TrimPrefix(args[i], "note=")
		} else if args[i] == "note" && i+1 < len(args) {
			// Support note "value" syntax (natural language style)
			params.Note = args[i+1]
			i++ // Skip the next argument since we consumed it
		} else if strings.HasPrefix(args[i], "fee=") {
			// Support fee=value syntax
			feeStr := strings.TrimPrefix(args[i], "fee=")
			feeVal, err := parseUint64(feeStr)
			if err != nil {
				return params, fmt.Errorf("invalid fee value: %s", feeStr)
			}
			params.Fee = feeVal
			params.UseFlatFee = true // User explicitly set fee
		} else if strings.HasPrefix(args[i], "arg:") {
			argName, argValue, err := ParseLsigArg(args[i])
			if err != nil {
				return params, err
			}
			if params.LsigArgs == nil {
				params.LsigArgs = make(map[string][]byte)
			}
			params.LsigArgs[argName] = argValue
		}
	}

	return params, nil
}

// ParseOptinCommand parses natural language optin syntax:
// optin <asset> for <account> [fee=<microalgos>] [nowait]
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
	params.ASARef = args[0]

	// Find "for" keyword
	forIdx := findKeyword(args, "for")
	if forIdx == -1 {
		return params, fmt.Errorf("missing 'for' keyword\nUsage: optin <asset> for <account>")
	}

	// Extract account (token after "for")
	if forIdx+1 >= len(args) {
		return params, fmt.Errorf("missing account after 'for'")
	}
	params.From = args[forIdx+1]

	// Parse optional flags
	for _, arg := range args {
		if arg == "nowait" {
			params.Wait = false
		} else if strings.HasPrefix(arg, "fee=") {
			feeStr := strings.TrimPrefix(arg, "fee=")
			feeVal, err := parseUint64(feeStr)
			if err != nil {
				return params, fmt.Errorf("invalid fee value: %s", feeStr)
			}
			params.Fee = feeVal
			params.UseFlatFee = true
		}
	}

	return params, nil
}

// ParseOptoutCommand parses natural language optout syntax:
// optout <asset> from <account> [to <dest>] [fee=<microalgos>] [nowait]
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
	params.ASARef = args[0]

	// Find "from" keyword
	fromIdx := findKeyword(args, "from")
	if fromIdx == -1 || fromIdx == 0 {
		return params, fmt.Errorf("missing 'from' keyword\nUsage: optout <asset> from <account>")
	}

	// Extract account (token after "from")
	if fromIdx+1 >= len(args) {
		return params, fmt.Errorf("missing account after 'from'")
	}
	params.Account = args[fromIdx+1]

	// Find optional "to" keyword for close-to address
	toIdx := findKeyword(args, "to")
	if toIdx != -1 && toIdx+1 < len(args) {
		// Make sure "to" is after "from" and not a flag
		nextArg := args[toIdx+1]
		if !strings.HasPrefix(nextArg, "fee=") && nextArg != "nowait" {
			params.CloseTo = nextArg
		}
	}

	// Parse optional flags
	for _, arg := range args {
		if arg == "nowait" {
			params.Wait = false
		} else if strings.HasPrefix(arg, "fee=") {
			feeStr := strings.TrimPrefix(arg, "fee=")
			feeVal, err := parseUint64(feeStr)
			if err != nil {
				return params, fmt.Errorf("invalid fee value: %s", feeStr)
			}
			params.Fee = feeVal
			params.UseFlatFee = true
		}
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

	// Find "to" keyword
	toIdx := findKeyword(args, "to")
	if toIdx == -1 || toIdx == 0 {
		return params, fmt.Errorf("missing 'to' keyword\nUsage: close <account> to <destination>")
	}

	// Extract destination (token after "to")
	if toIdx+1 >= len(args) {
		return params, fmt.Errorf("missing destination after 'to'")
	}
	params.CloseTo = args[toIdx+1]

	// Parse optional flags
	for _, arg := range args {
		if arg == "nowait" {
			params.Wait = false
		} else if strings.HasPrefix(arg, "fee=") {
			feeStr := strings.TrimPrefix(arg, "fee=")
			feeVal, err := parseUint64(feeStr)
			if err != nil {
				return params, fmt.Errorf("invalid fee value: %s", feeStr)
			}
			params.Fee = feeVal
			params.UseFlatFee = true
		} else if strings.HasPrefix(arg, "arg:") {
			argName, argValue, err := ParseLsigArg(arg)
			if err != nil {
				return params, err
			}
			if params.LsigArgs == nil {
				params.LsigArgs = make(map[string][]byte)
			}
			params.LsigArgs[argName] = argValue
		}
	}

	return params, nil
}

// ParseRekeyCommand parses natural language rekey syntax:
// rekey <account> to <signer> [fee=<microalgos>] [nowait]
// Also handles unrekey: unrekey <account> [fee=<microalgos>] [nowait]
func ParseRekeyCommand(args []string, isUnrekey bool) (RekeyParams, error) {
	params := RekeyParams{
		Wait:       true,
		Fee:        0,
		UseFlatFee: false,
	}

	if isUnrekey {
		// unrekey <account> [fee=<microalgos>] [nowait]
		if len(args) < 1 {
			return params, fmt.Errorf("usage: unrekey <account> [fee=<microalgos>] [nowait]\nExample: unrekey alice")
		}
		params.Account = args[0]
		params.Signer = args[0] // Rekey to self

		// Parse optional flags
		for _, arg := range args {
			if arg == "nowait" {
				params.Wait = false
			} else if strings.HasPrefix(arg, "fee=") {
				feeStr := strings.TrimPrefix(arg, "fee=")
				feeVal, err := parseUint64(feeStr)
				if err != nil {
					return params, fmt.Errorf("invalid fee value: %s", feeStr)
				}
				params.Fee = feeVal
				params.UseFlatFee = true
			}
		}
		return params, nil
	}

	// rekey <account> to <signer> [nowait]
	if len(args) < 3 {
		return params, fmt.Errorf("usage: rekey <account> to <signer> [nowait]\nExample: rekey alice to bob")
	}

	// Position 0: account
	params.Account = args[0]

	// Find "to" keyword
	toIdx := findKeyword(args, "to")
	if toIdx == -1 {
		return params, fmt.Errorf("missing 'to' keyword\nUsage: rekey <account> to <signer>")
	}

	// Extract signer (token after "to")
	if toIdx+1 >= len(args) {
		return params, fmt.Errorf("missing signer after 'to'")
	}
	params.Signer = args[toIdx+1]

	// Parse optional flags
	for _, arg := range args {
		if arg == "nowait" {
			params.Wait = false
		} else if strings.HasPrefix(arg, "fee=") {
			feeStr := strings.TrimPrefix(arg, "fee=")
			feeVal, err := parseUint64(feeStr)
			if err != nil {
				return params, fmt.Errorf("invalid fee value: %s", feeStr)
			}
			params.Fee = feeVal
			params.UseFlatFee = true
		}
	}

	return params, nil
}

// ParseTakeCommand parses natural language keyreg syntax:
// keyreg <account> <online|offline> [votekey=...] [selkey=...] [sproofkey=...] [votefirst=...] [votelast=...] [keydilution=...] [eligible=true] [nowait]
func ParseTakeCommand(args []string) (KeyRegParams, error) {
	params := KeyRegParams{
		Wait:              true,
		IncentiveEligible: false, // Default to NOT eligible (requires explicit flag)
		VoteFirst:         0,
		VoteLast:          3000000,
		KeyDilution:       10000,
	}

	if len(args) < 2 {
		return params, fmt.Errorf("usage: keyreg <account> <online|offline> [votekey=...] [selkey=...] [sproofkey=...] [nowait]\nExample: keyreg alice online votekey=ABC selkey=DEF sproofkey=GHI")
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

// parseUint64 is a helper to parse uint64 values
// ParseLsigArg parses an "arg:name=value" token.
// Values are treated as UTF-8 strings by default.
// Use 0x prefix to pass raw hex-encoded bytes: arg:preimage=0x68656c6c6f
func ParseLsigArg(token string) (string, []byte, error) {
	argPart := strings.TrimPrefix(token, "arg:")
	eqIdx := strings.Index(argPart, "=")
	if eqIdx == -1 {
		return "", nil, fmt.Errorf("invalid arg syntax, expected arg:name=value, got: %s", token)
	}
	argName := argPart[:eqIdx]
	argValueRaw := argPart[eqIdx+1:]

	// 0x prefix: decode as hex bytes
	if strings.HasPrefix(argValueRaw, "0x") {
		argValue, err := hex.DecodeString(argValueRaw[2:])
		if err != nil {
			return "", nil, fmt.Errorf("invalid hex in arg:%s: %v", argName, err)
		}
		return argName, argValue, nil
	}

	// Default: treat as UTF-8 string
	return argName, []byte(argValueRaw), nil
}

func parseUint64(s string) (uint64, error) {
	val, err := fmt.Sscanf(s, "%d", new(uint64))
	if err != nil || val != 1 {
		return 0, fmt.Errorf("invalid uint64: %s", s)
	}
	var result uint64
	_, _ = fmt.Sscanf(s, "%d", &result)
	return result, nil
}

// SweepParams holds parsed parameters for sweep command
type SweepParams struct {
	Asset      string   // "algo" or ASA name/ID
	FromRaw    []string // Raw source inputs (aliases, addresses, @setnames) - nil means all signable
	ToRaw      string   // Raw destination input (alias, address)
	Leaving    string   // Amount to leave in each source (optional)
	Wait       bool
	Fee        uint64 // transaction fee in microAlgos
	UseFlatFee bool   // true if user explicitly set fee (even if zero)
}

// ParseSweepCommand parses sweep syntax:
// sweep <asset> from [account1 account2 ...] to <dest> [leaving <amount>] [fee=<microalgos>] [nowait]
// sweep <asset> to <dest> [leaving <amount>] [fee=<microalgos>] [nowait]  (uses all signable accounts)
func ParseSweepCommand(args []string) (SweepParams, error) {
	params := SweepParams{
		Wait:       true,
		Fee:        0,
		UseFlatFee: false,
		Leaving:    "0", // Default: sweep everything
		FromRaw:    nil, // nil = use all signable accounts
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
	params.Asset = args[0]

	// Find keyword positions
	fromIdx := findKeyword(args, "from")
	toIdx := findKeyword(args, "to")
	leavingIdx := findKeyword(args, "leaving")

	if toIdx == -1 {
		return params, fmt.Errorf("missing 'to' keyword")
	}

	// Extract destination (token after "to")
	if toIdx+1 >= len(args) {
		return params, fmt.Errorf("missing destination after 'to'")
	}
	params.ToRaw = args[toIdx+1]

	// If "from" keyword is present, parse the account set
	if fromIdx != -1 {
		// Extract source accounts from set [...] or @setname
		// Look for '[' or '@' after "from"
		if fromIdx+1 >= len(args) {
			return params, fmt.Errorf("missing accounts after 'from'")
		}

		var accounts []string
		var endIdx int
		var err error

		// Check if it's a @setname reference
		if len(args[fromIdx+1]) > 0 && args[fromIdx+1][0] == '@' {
			// Store the set reference as-is (will be resolved later with access to SetCache)
			params.FromRaw = []string{args[fromIdx+1]}
			endIdx = fromIdx + 1
		} else {
			// Parse the bracket set syntax [account1 account2 ...]
			accounts, endIdx, err = parseAccountSet(args, fromIdx+1)
			if err != nil {
				return params, fmt.Errorf("failed to parse account set: %w", err)
			}
			params.FromRaw = accounts

			// Make sure we found at least one account
			if len(params.FromRaw) == 0 {
				return params, fmt.Errorf("no accounts specified in set")
			}
		}

		// Update toIdx if it was found after the set
		if endIdx >= toIdx {
			// Re-find "to" keyword after the set
			toIdx = findKeyword(args[endIdx+1:], "to")
			if toIdx == -1 {
				return params, fmt.Errorf("missing 'to' keyword after account set")
			}
			toIdx += endIdx + 1 // Adjust index
			if toIdx+1 >= len(args) {
				return params, fmt.Errorf("missing destination after 'to'")
			}
			params.ToRaw = args[toIdx+1]

			// Re-find "leaving" if present
			leavingIdx = findKeyword(args[endIdx+1:], "leaving")
			if leavingIdx != -1 {
				leavingIdx += endIdx + 1 // Adjust index
			}
		}
	}
	// else: params.FromRaw remains nil, meaning "use all signable accounts"

	// Parse optional "leaving" amount
	if leavingIdx != -1 {
		if leavingIdx+1 >= len(args) {
			return params, fmt.Errorf("missing amount after 'leaving'")
		}
		params.Leaving = args[leavingIdx+1]
	}

	// Parse optional flags
	for i := 0; i < len(args); i++ {
		if args[i] == "nowait" {
			params.Wait = false
		} else if strings.HasPrefix(args[i], "fee=") {
			feeStr := strings.TrimPrefix(args[i], "fee=")
			feeVal, err := parseUint64(feeStr)
			if err != nil {
				return params, fmt.Errorf("invalid fee value: %s", feeStr)
			}
			params.Fee = feeVal
			params.UseFlatFee = true
		}
	}

	return params, nil
}

// parseAccountSet parses the [account1 account2 ...] syntax starting at the given index
// Returns the accounts slice and the index of the closing bracket
func parseAccountSet(args []string, startIdx int) ([]string, int, error) {
	// Check if we have '['
	if startIdx >= len(args) || args[startIdx] != "[" {
		return nil, startIdx, fmt.Errorf("expected '[' to start account set")
	}

	var accounts []string
	i := startIdx + 1

	// Collect accounts until we find ']'
	for i < len(args) {
		if args[i] == "]" {
			return accounts, i, nil
		}
		accounts = append(accounts, args[i])
		i++
	}

	return nil, startIdx, fmt.Errorf("missing closing ']' for account set")
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
