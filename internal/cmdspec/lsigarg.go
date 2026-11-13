// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cmdspec

import (
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/appinput"
)

// LsigArg is one LogicSig argument word as it was written:
//
//	arg:<name>=<value>           Target empty: every transaction the command builds
//	arg:<target>:<name>=<value>  Target an address or an alias: the transactions that account sends
//
// The parser cannot resolve a target; the command resolves it against the
// accounts it sends from.
type LsigArg struct {
	Target string
	Name   string
	Value  []byte
}

// Untargeted reports whether the word names no account, and so is for every
// transaction the command builds.
func (a LsigArg) Untargeted() bool { return a.Target == "" }

// Word is how messages name the argument: arg:<name> or arg:<target>:<name>.
// It leaves the value out, which may be a secret such as a preimage.
func (a LsigArg) Word() string {
	if a.Untargeted() {
		return "arg:" + a.Name
	}
	return "arg:" + a.Target + ":" + a.Name
}

// LsigArgs is a command's arg: words in the order they were given.
type LsigArgs []LsigArg

// ParseLsigArg parses an "arg:<name>=<value>" or "arg:<target>:<name>=<value>"
// token. The token is split at its first "=", so the value may hold ":" and
// "=" (as in hex:abcd). The part before it is the name alone when it holds no
// ":", and the target and the name when it holds one; more than one ":", an
// empty target or an empty name is refused. So an argument name may not hold
// ":", which is what keeps the two forms apart. A target that names a set is
// refused: a target is one account. The value side is decoded via the shared
// byte-value grammar in appinput.
func ParseLsigArg(token string) (LsigArg, error) {
	const expected = "expected arg:<name>=<value> or arg:<account>:<name>=<value>"
	body, ok := strings.CutPrefix(token, "arg:")
	if !ok {
		return LsigArg{}, fmt.Errorf("invalid LogicSig argument %q: %s", token, expected)
	}
	head, rawValue, ok := strings.Cut(body, "=")
	if !ok {
		return LsigArg{}, fmt.Errorf("invalid LogicSig argument %q: %s", token, expected)
	}
	var arg LsigArg
	switch strings.Count(head, ":") {
	case 0:
		arg.Name = head
	case 1:
		arg.Target, arg.Name, _ = strings.Cut(head, ":")
		if arg.Target == "" {
			return LsigArg{}, fmt.Errorf("arg:%s=...: the account before the name is empty: %s", head, expected)
		}
		if strings.HasPrefix(arg.Target, "@") {
			return LsigArg{}, fmt.Errorf("arg:%s=...: a set cannot be the account an argument is for: name one account (an address or an alias), or leave it out for every transaction", head)
		}
	default:
		return LsigArg{}, fmt.Errorf("arg:%s=...: too many ':' (an argument name may not contain ':'): %s", head, expected)
	}
	if arg.Name == "" {
		return LsigArg{}, fmt.Errorf("arg:%s=...: the argument name is empty: %s", head, expected)
	}
	value, err := appinput.ParseByteValue(rawValue)
	if err != nil {
		return LsigArg{}, fmt.Errorf("invalid %s: %w", arg.Word(), err)
	}
	arg.Value = value
	return arg, nil
}

// AddLsigArg parses an arg: token and appends it to args. A name given twice
// with no target, or twice for a target written the same way, is refused,
// because the second value would contradict the first. The repeats that
// depend on what a target resolves to (an alias and its address, two aliases
// for one account, a name given both with no target and for an account) are
// refused once the command resolves its targets.
func AddLsigArg(args *LsigArgs, token string) error {
	arg, err := ParseLsigArg(token)
	if err != nil {
		return err
	}
	for _, given := range *args {
		if given.Target == arg.Target && given.Name == arg.Name {
			return fmt.Errorf("%s given more than once", arg.Word())
		}
	}
	*args = append(*args, arg)
	return nil
}
