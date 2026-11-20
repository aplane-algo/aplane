// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package externalcheck

import (
	"fmt"
	"math/big"
	"slices"
	"strings"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/strictjson"
)

// maxQuotedValue is how much of an answer's string the audit record quotes.
const maxQuotedValue = 64

// Judge applies check to answer for a unit with facts. requestID is the ID the
// lookup was sent with. It returns whether every rule holds and, when one does
// not, what failed. A rule holds only on a value of the right type: a missing
// value, a null and a value of another type all fail, for ne and not_in too.
func Judge(check policy.ExternalCheckV1, facts Facts, answer *strictjson.Node, requestID string) (bool, string) {
	if check.EchoPointer != nil {
		echo, ok := answer.Resolve(*check.EchoPointer)
		if !ok || echo.Kind != strictjson.String || echo.Text != requestID {
			return false, "echo mismatch: " + describePointer(*check.EchoPointer) + " is not the request ID that was sent"
		}
	}
	for _, rule := range check.Require {
		if ok, detail := judgeRule(rule, facts, answer); !ok {
			return false, detail
		}
	}
	return true, ""
}

func judgeRule(rule policy.ExternalRuleV1, facts Facts, answer *strictjson.Node) (bool, string) {
	where := describePointer(rule.Pointer)
	value, found := answer.Resolve(rule.Pointer)
	switch rule.Op {
	case policy.ExternalOpPresent:
		if !found {
			return false, where + " missing"
		}
		return true, ""
	case policy.ExternalOpAbsent:
		if found {
			return false, where + " is present, want it absent"
		}
		return true, ""
	}
	if !found {
		return false, where + " missing"
	}
	switch {
	case rule.Bool != nil:
		if value.Kind != strictjson.Bool {
			return false, wrongType(where, value, "a boolean")
		}
		return verdict(where, value, rule, (value.Bool == *rule.Bool) == (rule.Op == policy.ExternalOpEq), fmt.Sprint(*rule.Bool))
	case rule.String != nil:
		return judgeString(where, value, rule, *rule.String)
	case rule.Number != nil:
		return judgeNumber(where, value, rule, *rule.Number)
	case rule.Strings != nil:
		if value.Kind != strictjson.String {
			return false, wrongType(where, value, "a string")
		}
		in := slices.Contains(rule.Strings, value.Text)
		return verdict(where, value, rule, in == (rule.Op == policy.ExternalOpIn), "the listed strings")
	case rule.Numbers != nil:
		return judgeNumberList(where, value, rule)
	case rule.Fact != "":
		operand, has := facts[rule.Fact]
		if !has {
			return false, "the unit has no " + rule.Fact
		}
		if fact, _ := policy.LookupExternalFact(policy.ExternalScopeMovement, rule.Fact); fact.Numeric {
			return judgeNumber(where, value, rule, operand)
		}
		return judgeString(where, value, rule, operand)
	}
	return false, where + ": the rule has no operand"
}

func judgeString(where string, value *strictjson.Node, rule policy.ExternalRuleV1, operand string) (bool, string) {
	if value.Kind != strictjson.String {
		return false, wrongType(where, value, "a string")
	}
	return verdict(where, value, rule, (value.Text == operand) == (rule.Op == policy.ExternalOpEq), quote(operand))
}

// judgeNumber compares exact decimals: 1, 1.0 and 1e0 are equal, and -0
// equals 0.
func judgeNumber(where string, value *strictjson.Node, rule policy.ExternalRuleV1, operand string) (bool, string) {
	got, ok := numberOf(value)
	if !ok {
		return false, wrongType(where, value, "a number")
	}
	want, ok := new(big.Rat).SetString(operand)
	if !ok {
		return false, where + ": the rule's number does not parse"
	}
	cmp := got.Cmp(want)
	var holds bool
	switch rule.Op {
	case policy.ExternalOpEq:
		holds = cmp == 0
	case policy.ExternalOpNe:
		holds = cmp != 0
	case policy.ExternalOpLt:
		holds = cmp < 0
	case policy.ExternalOpLe:
		holds = cmp <= 0
	case policy.ExternalOpGt:
		holds = cmp > 0
	case policy.ExternalOpGe:
		holds = cmp >= 0
	}
	return verdict(where, value, rule, holds, operand)
}

func judgeNumberList(where string, value *strictjson.Node, rule policy.ExternalRuleV1) (bool, string) {
	got, ok := numberOf(value)
	if !ok {
		return false, wrongType(where, value, "a number")
	}
	in := false
	for _, raw := range rule.Numbers {
		if want, ok := new(big.Rat).SetString(raw); ok && got.Cmp(want) == 0 {
			in = true
			break
		}
	}
	return verdict(where, value, rule, in == (rule.Op == policy.ExternalOpIn), "the listed numbers")
}

// numberOf reads a JSON number exactly. The reader has bounded its literal.
func numberOf(value *strictjson.Node) (*big.Rat, bool) {
	if value.Kind != strictjson.Number {
		return nil, false
	}
	return new(big.Rat).SetString(value.Text)
}

func verdict(where string, value *strictjson.Node, rule policy.ExternalRuleV1, holds bool, operand string) (bool, string) {
	if holds {
		return true, ""
	}
	return false, fmt.Sprintf("%s = %s, want %s %s", where, describeValue(value), rule.Op, operand)
}

func wrongType(where string, value *strictjson.Node, want string) string {
	return fmt.Sprintf("%s is %s, want %s", where, article(value.Kind), want)
}

func article(kind strictjson.Kind) string {
	switch kind {
	case strictjson.Null:
		return "null"
	case strictjson.Object, strictjson.Array:
		return "an " + kind.String()
	default:
		return "a " + kind.String()
	}
}

func describePointer(pointer string) string {
	if pointer == "" {
		return "the answer"
	}
	return quoteBare(pointer)
}

// describeValue renders an answer's value for the audit record: scalars as
// they are, a string quoted and cut short, a container by its kind.
func describeValue(value *strictjson.Node) string {
	switch value.Kind {
	case strictjson.Bool:
		return fmt.Sprint(value.Bool)
	case strictjson.Number:
		return value.Text
	case strictjson.String:
		return quote(value.Text)
	default:
		return article(value.Kind)
	}
}

// quote renders s for the audit record: cut to maxQuotedValue characters, in
// double quotes, with control and non-ASCII characters escaped.
func quote(s string) string {
	return `"` + quoteBare(s) + `"`
}

func quoteBare(s string) string {
	cut := false
	if len(s) > maxQuotedValue {
		s, cut = s[:maxQuotedValue], true
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r >= 0x7f:
			fmt.Fprintf(&b, "\\u%04x", r)
		default:
			b.WriteRune(r)
		}
	}
	if cut {
		b.WriteString("...")
	}
	return b.String()
}
