// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package avmsim is test support only: a small interpreter for the TEAL subset
// APlane's own programs use, so a test can run the real program source offline.
// The rotating stage tests run their verifiers in it against the Go primitive,
// and the bounded agreement test runs every rendered bounded program in it
// against the signer's planner. No production code may import it.
//
// It models the AVM's stack, scratch space, subroutines and the 4096-byte value
// limit, and refuses any opcode, field or literal form it does not know: a
// program edit that reaches for something new fails the test until the
// interpreter learns it, which keeps the interpreter honest instead of
// silently skipping or zero-filling what it cannot run. It is not an AVM:
// costs, groups and the signature opcodes are out of scope, and a test
// supplies the transaction fields the program reads and hooks for the
// signature opcodes.
package avmsim

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

const (
	avmMaxBytes = 4096
	avmMaxStack = 1000
	avmMaxSteps = 20_000_000
	// avmMaxByteMath is the longest operand the byte-math opcodes (b<) accept.
	avmMaxByteMath = 64
)

// Value is one stack value.
type Value struct {
	bytes   []byte
	uint    uint64
	isBytes bool
}

// Bytes returns a byte value's contents, or nil for an integer.
func (v Value) Bytes() []byte { return v.bytes }

// Uint returns an integer value's contents, or zero for a byte value.
func (v Value) Uint() uint64 { return v.uint }

// U builds an integer value, for a transaction field.
func U(u uint64) Value { return Value{uint: u} }

// B builds a byte value, for a transaction field.
func B(b []byte) Value { return Value{bytes: b, isBytes: true} }

type avmInstr struct {
	op   string
	args []string
	// literal is a pushbytes or pushint immediate decoded once at assembly, or
	// literalErr why it could not be; Run reports that error when it reaches the
	// instruction, so a bad literal on a path never run stays harmless.
	literal    Value
	literalErr error
}

// Txn is the transaction the program sees, by AVM field name (TxID, Sender,
// TypeEnum, ...). A field the program reads that the map lacks is an
// UnsupportedError, never a zero value: a test states every field it means
// the program to see, including the zero values the AVM reports for fields of
// another transaction type.
type Txn map[string]Value

// Hooks run the signature opcodes the interpreter does not implement. A
// hook receives the data, signature and key and returns whether it verifies.
type Hooks struct {
	Ed25519 func(data, sig, key []byte) bool
	Falcon  func(data, sig, key []byte) bool
	// Equal observes the operands of every == and !=, so a test can pin
	// what a verifier's final comparison actually compares.
	Equal func(a, b Value)
}

// Program is assembled TEAL source.
type Program struct {
	code   []avmInstr
	labels map[string]int
}

// Assemble reads TEAL source: one instruction or label per line, // comments
// and the #pragma line ignored. It checks labels for duplicates only; every
// other problem surfaces when Run reaches it.
func Assemble(src string) (*Program, error) {
	p := &Program{labels: map[string]int{}}
	for n, line := range strings.Split(src, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] == "#pragma" {
			continue
		}
		if len(fields) == 1 && strings.HasSuffix(fields[0], ":") {
			label := strings.TrimSuffix(fields[0], ":")
			if _, dup := p.labels[label]; dup {
				return nil, fmt.Errorf("line %d: duplicate label %s", n+1, label)
			}
			p.labels[label] = len(p.code)
			continue
		}
		in := avmInstr{op: fields[0], args: fields[1:]}
		in.literal, in.literalErr = decodeLiteral(in)
		p.code = append(p.code, in)
	}
	return p, nil
}

// decodeLiteral decodes a pushbytes or pushint immediate. Only 0x hexadecimal
// byte literals and decimal or 0x integer literals are understood; named
// constants (NoOp, Pay, ...), base64 and string literals are not.
func decodeLiteral(in avmInstr) (Value, error) {
	switch in.op {
	case "pushint", "int":
		if len(in.args) != 1 {
			return Value{}, unsupportedf("%s with %d immediates", in.op, len(in.args))
		}
		u, err := strconv.ParseUint(in.args[0], 0, 64)
		if err != nil {
			return Value{}, unsupportedf("%s literal %q", in.op, in.args[0])
		}
		return U(u), nil
	case "pushbytes":
		if len(in.args) != 1 || !strings.HasPrefix(in.args[0], "0x") {
			return Value{}, unsupportedf("pushbytes literal %q (only 0x hexadecimal is understood)", strings.Join(in.args, " "))
		}
		b, err := hex.DecodeString(strings.TrimPrefix(in.args[0], "0x"))
		if err != nil {
			return Value{}, unsupportedf("pushbytes literal %q: %v", in.args[0], err)
		}
		return B(b), nil
	}
	return Value{}, nil
}

// ErrReject reports a program that ended without approving: it fell off the
// end without exactly one nonzero integer on the stack.
var ErrReject = errors.New("program rejected")

// UnsupportedError reports something the interpreter cannot model: an
// unknown opcode, an unsupported field, a missing hook, a bad label or
// immediate, or a step limit. It is distinct from a modeled AVM fault
// (overflow, out-of-range slice, type error), which rejects the transaction
// on chain too. A harness must fail on it, never read it as a rejection.
type UnsupportedError struct{ msg string }

func (e *UnsupportedError) Error() string { return "unsupported by the interpreter: " + e.msg }

func unsupportedf(format string, a ...any) error {
	return &UnsupportedError{msg: fmt.Sprintf(format, a...)}
}

// Run executes the program and reports whether it approves. A failed assert,
// err, or a zero return rejects with a nil error. A runtime fault (type error,
// overflow, out-of-range slice or argument, oversized value) is an error, as
// it is on the AVM, and means the transaction is rejected too.
func (p *Program) Run(txn Txn, args [][]byte, hooks Hooks) (bool, error) {
	var (
		stack = make([]Value, 0, 32)
		// scratch is allocated on first use: most programs never touch it.
		scratch *[256]Value
		calls   []int
		pc      int
		steps   int
	)
	fail := func(err error) (bool, error) {
		return false, fmt.Errorf("pc %d %s: %w", pc, p.code[pc].op, err)
	}
	pop := func() (Value, error) {
		if len(stack) == 0 {
			return Value{}, errors.New("stack underflow")
		}
		v := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		return v, nil
	}
	popUint := func() (uint64, error) {
		v, err := pop()
		if err == nil && v.isBytes {
			err = errors.New("expected uint64, have bytes")
		}
		return v.uint, err
	}
	popBytes := func() ([]byte, error) {
		v, err := pop()
		if err == nil && !v.isBytes {
			err = errors.New("expected bytes, have uint64")
		}
		return v.bytes, err
	}
	push := func(v Value) error {
		if len(stack) >= avmMaxStack {
			return errors.New("stack overflow")
		}
		stack = append(stack, v)
		return nil
	}
	jump := func(label string) error {
		target, ok := p.labels[label]
		if !ok {
			return unsupportedf("unknown label %s", label)
		}
		pc = target - 1 // the loop increments
		return nil
	}
	imm := func(i int) (int, error) {
		in := p.code[pc]
		if i >= len(in.args) {
			return 0, unsupportedf("missing immediate")
		}
		n, err := strconv.Atoi(in.args[i])
		if err != nil || n < 0 {
			return 0, unsupportedf("bad immediate %q", in.args[i])
		}
		return n, nil
	}

	for pc = 0; pc < len(p.code); pc++ {
		if steps++; steps > avmMaxSteps {
			return fail(unsupportedf("step limit"))
		}
		in := p.code[pc]
		var err error
		switch in.op {
		case "txn", "global", "callsub", "b", "bz", "bnz":
			if len(in.args) != 1 {
				return fail(unsupportedf("%s with %d immediates", in.op, len(in.args)))
			}
		}
		switch in.op {
		case "pushint", "int", "pushbytes":
			// Pushed byte literals are shared across runs; no opcode writes a
			// value in place, so sharing them is safe.
			if err = in.literalErr; err == nil {
				err = push(in.literal)
			}
		case "load":
			var n int
			if n, err = imm(0); err == nil {
				if n > 255 {
					err = errors.New("scratch slot out of range")
				} else if scratch == nil {
					err = push(Value{})
				} else {
					err = push(scratch[n])
				}
			}
		case "store":
			var n int
			var v Value
			if n, err = imm(0); err == nil {
				if n > 255 {
					err = errors.New("scratch slot out of range")
				} else if v, err = pop(); err == nil {
					if scratch == nil {
						scratch = new([256]Value)
					}
					scratch[n] = v
				}
			}
		case "txn":
			v, ok := txn[in.args[0]]
			if !ok {
				err = unsupportedf("txn field %s not supplied", in.args[0])
			} else {
				err = push(v)
			}
		case "global":
			if in.args[0] != "ZeroAddress" {
				err = unsupportedf("global %s", in.args[0])
			} else {
				err = push(B(make([]byte, 32)))
			}
		case "arg":
			var n int
			if n, err = imm(0); err == nil {
				if n >= len(args) {
					err = errors.New("arg index out of range")
				} else {
					err = push(B(args[n]))
				}
			}
		case "assert":
			var u uint64
			if u, err = popUint(); err == nil && u == 0 {
				return false, nil
			}
		case "err":
			return false, nil
		case "return":
			var u uint64
			u, err = popUint()
			return err == nil && u != 0, err
		case "b":
			err = jump(in.args[0])
		case "bz", "bnz":
			var u uint64
			if u, err = popUint(); err == nil && (u == 0) == (in.op == "bz") {
				err = jump(in.args[0])
			}
		case "switch":
			var u uint64
			if u, err = popUint(); err == nil && u < uint64(len(in.args)) {
				err = jump(in.args[u])
			}
		case "callsub":
			calls = append(calls, pc)
			err = jump(in.args[0])
		case "retsub":
			if len(calls) == 0 {
				err = errors.New("retsub without callsub")
			} else {
				pc = calls[len(calls)-1]
				calls = calls[:len(calls)-1]
			}
		case "dup":
			if len(stack) == 0 {
				err = errors.New("stack underflow")
			} else {
				err = push(stack[len(stack)-1])
			}
		case "dup2":
			if len(stack) < 2 {
				err = errors.New("stack underflow")
			} else {
				a, b := stack[len(stack)-2], stack[len(stack)-1]
				if err = push(a); err == nil {
					err = push(b)
				}
			}
		case "pop":
			_, err = pop()
		case "swap":
			var a, b Value
			if b, err = pop(); err == nil {
				if a, err = pop(); err == nil {
					err = push(b)
					if err == nil {
						err = push(a)
					}
				}
			}
		case "select":
			var c uint64
			var a, b Value
			if c, err = popUint(); err == nil {
				if b, err = pop(); err == nil {
					if a, err = pop(); err == nil {
						if c != 0 {
							err = push(b)
						} else {
							err = push(a)
						}
					}
				}
			}
		case "!":
			var u uint64
			if u, err = popUint(); err == nil {
				err = push(U(boolUint(u == 0)))
			}
		case "+", "-", "*", "/", "&", "<", "<=", ">", ">=", "&&", "||", "shl", "shr":
			var a, b uint64
			if b, err = popUint(); err == nil {
				if a, err = popUint(); err == nil {
					var r uint64
					r, err = uintOp(in.op, a, b)
					if err == nil {
						err = push(U(r))
					}
				}
			}
		case "==", "!=":
			var a, b Value
			if b, err = pop(); err == nil {
				if a, err = pop(); err == nil {
					if a.isBytes != b.isBytes {
						err = errors.New("comparing bytes with uint64")
					} else {
						if hooks.Equal != nil {
							hooks.Equal(a, b)
						}
						eq := a.uint == b.uint
						if a.isBytes {
							eq = string(a.bytes) == string(b.bytes)
						}
						err = push(U(boolUint(eq == (in.op == "=="))))
					}
				}
			}
		case "b<":
			var a, b []byte
			if b, err = popBytes(); err == nil {
				if a, err = popBytes(); err == nil {
					if len(a) > avmMaxByteMath || len(b) > avmMaxByteMath {
						err = fmt.Errorf("b< operand longer than %d bytes", avmMaxByteMath)
					} else {
						err = push(U(boolUint(new(big.Int).SetBytes(a).Cmp(new(big.Int).SetBytes(b)) < 0)))
					}
				}
			}
		case "itob":
			var u uint64
			if u, err = popUint(); err == nil {
				err = push(B(binary.BigEndian.AppendUint64(nil, u)))
			}
		case "btoi":
			var b []byte
			if b, err = popBytes(); err == nil {
				if len(b) > 8 {
					err = errors.New("btoi input longer than 8 bytes")
				} else {
					var u uint64
					for _, c := range b {
						u = u<<8 | uint64(c)
					}
					err = push(U(u))
				}
			}
		case "len":
			var b []byte
			if b, err = popBytes(); err == nil {
				err = push(U(uint64(len(b))))
			}
		case "sha256":
			var b []byte
			if b, err = popBytes(); err == nil {
				sum := sha256.Sum256(b)
				err = push(B(sum[:]))
			}
		case "sha512_256":
			var b []byte
			if b, err = popBytes(); err == nil {
				sum := sha512.Sum512_256(b)
				err = push(B(sum[:]))
			}
		case "concat":
			var a, b []byte
			if b, err = popBytes(); err == nil {
				if a, err = popBytes(); err == nil {
					if len(a)+len(b) > avmMaxBytes {
						err = errors.New("concat result exceeds 4096 bytes")
					} else {
						err = push(B(append(append(make([]byte, 0, len(a)+len(b)), a...), b...)))
					}
				}
			}
		case "bzero":
			var n uint64
			if n, err = popUint(); err == nil {
				if n > avmMaxBytes {
					err = errors.New("bzero exceeds 4096 bytes")
				} else {
					err = push(B(make([]byte, n)))
				}
			}
		case "extract":
			var s, l int
			var a []byte
			if s, err = imm(0); err == nil {
				if l, err = imm(1); err == nil {
					if a, err = popBytes(); err == nil {
						err = pushExtract(push, a, uint64(s), uint64(l), l == 0)
					}
				}
			}
		case "extract3":
			var s, l uint64
			var a []byte
			if l, err = popUint(); err == nil {
				if s, err = popUint(); err == nil {
					if a, err = popBytes(); err == nil {
						err = pushExtract(push, a, s, l, false)
					}
				}
			}
		case "replace2":
			var s int
			var a, b []byte
			if s, err = imm(0); err == nil {
				if b, err = popBytes(); err == nil {
					if a, err = popBytes(); err == nil {
						if s+len(b) > len(a) {
							err = errors.New("replace2 out of range")
						} else {
							out := append([]byte(nil), a...)
							copy(out[s:], b)
							err = push(B(out))
						}
					}
				}
			}
		case "getbyte":
			var i uint64
			var a []byte
			if i, err = popUint(); err == nil {
				if a, err = popBytes(); err == nil {
					if i >= uint64(len(a)) {
						err = errors.New("getbyte index out of range")
					} else {
						err = push(U(uint64(a[i])))
					}
				}
			}
		case "setbyte":
			var v, i uint64
			var a []byte
			if v, err = popUint(); err == nil {
				if i, err = popUint(); err == nil {
					if a, err = popBytes(); err == nil {
						if i >= uint64(len(a)) || v > 255 {
							err = errors.New("setbyte out of range")
						} else {
							out := append([]byte(nil), a...)
							out[i] = byte(v)
							err = push(B(out))
						}
					}
				}
			}
		case "ed25519verify_bare", "falcon_verify":
			var data, sig, key []byte
			if key, err = popBytes(); err == nil {
				if sig, err = popBytes(); err == nil {
					if data, err = popBytes(); err == nil {
						verify := hooks.Ed25519
						if in.op == "falcon_verify" {
							verify = hooks.Falcon
						}
						if verify == nil {
							err = unsupportedf("no hook for %s", in.op)
						} else {
							err = push(U(boolUint(verify(data, sig, key))))
						}
					}
				}
			}
		default:
			err = unsupportedf("opcode %q", in.op)
		}
		if err != nil {
			return fail(err)
		}
	}
	// Falling off the end approves only with exactly one nonzero value left.
	if len(stack) == 1 && !stack[0].isBytes && stack[0].uint != 0 {
		return true, nil
	}
	return false, ErrReject
}

func boolUint(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

func pushExtract(push func(Value) error, a []byte, s, l uint64, toEnd bool) error {
	if s > uint64(len(a)) {
		return errors.New("extract start out of range")
	}
	end := s + l
	if toEnd {
		end = uint64(len(a))
	}
	if end > uint64(len(a)) || end < s {
		return errors.New("extract out of range")
	}
	return push(B(append([]byte(nil), a[s:end]...)))
}

func uintOp(op string, a, b uint64) (uint64, error) {
	switch op {
	case "+":
		if r := a + b; r >= a {
			return r, nil
		}
		return 0, errors.New("+ overflowed")
	case "-":
		if b > a {
			return 0, errors.New("- underflowed")
		}
		return a - b, nil
	case "*":
		if a != 0 && (a*b)/a != b {
			return 0, errors.New("* overflowed")
		}
		return a * b, nil
	case "/":
		if b == 0 {
			return 0, errors.New("/ by zero")
		}
		return a / b, nil
	case "&":
		return a & b, nil
	case "<":
		return boolUint(a < b), nil
	case "<=":
		return boolUint(a <= b), nil
	case ">":
		return boolUint(a > b), nil
	case ">=":
		return boolUint(a >= b), nil
	case "&&":
		return boolUint(a != 0 && b != 0), nil
	case "||":
		return boolUint(a != 0 || b != 0), nil
	case "shl", "shr":
		if b >= 64 {
			return 0, fmt.Errorf("%s by %d", op, b)
		}
		if op == "shl" {
			return a << b, nil
		}
		return a >> b, nil
	}
	return 0, unsupportedf("operator %s", op)
}
