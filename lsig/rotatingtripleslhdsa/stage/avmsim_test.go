// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package stage

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// avmSim is a small interpreter for the TEAL subset the SLH-DSA stage
// verifiers use, so a test can run the real verifier source offline and
// compare it with the Go primitive. It models the AVM's stack, scratch space,
// subroutines and the 4096-byte value limit, and refuses any opcode it does
// not know: a verifier edit that reaches for a new opcode fails the test
// until the interpreter learns it, which keeps the interpreter honest instead
// of silently skipping what it cannot run. It is not an AVM: costs, groups
// and most transaction fields are out of scope.

const (
	avmMaxBytes = 4096
	avmMaxStack = 1000
	avmMaxSteps = 20_000_000
)

type avmValue struct {
	bytes   []byte
	uint    uint64
	isBytes bool
}

func avmUint(u uint64) avmValue  { return avmValue{uint: u} }
func avmBytes(b []byte) avmValue { return avmValue{bytes: b, isBytes: true} }

type avmInstr struct {
	op   string
	args []string
}

// avmTxn is the transaction the program sees.
type avmTxn struct {
	TxID, Sender, RekeyTo, CloseRemainderTo []byte
	FirstValid, LastValid                   uint64
}

// avmHooks run the signature opcodes the interpreter does not implement. A
// hook receives the data, signature and key and returns whether it verifies.
type avmHooks struct {
	Ed25519 func(data, sig, key []byte) bool
	Falcon  func(data, sig, key []byte) bool
	// Equal observes the operands of every == and !=, so a test can pin
	// what a verifier's final comparison actually compares.
	Equal func(a, b avmValue)
}

type avmProgram struct {
	code   []avmInstr
	labels map[string]int
}

func avmAssemble(src string) (*avmProgram, error) {
	p := &avmProgram{labels: map[string]int{}}
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
		p.code = append(p.code, avmInstr{op: fields[0], args: fields[1:]})
	}
	return p, nil
}

var errAVMReject = errors.New("program rejected")

// run executes the program and reports whether it approves. A runtime fault
// (type error, overflow, out-of-range slice, oversized value) is an error,
// as it is on the AVM, and means the transaction is rejected too.
func (p *avmProgram) run(txn avmTxn, args [][]byte, hooks avmHooks) (bool, error) {
	var (
		stack   []avmValue
		scratch [256]avmValue
		calls   []int
		pc      int
		steps   int
	)
	fail := func(format string, a ...any) (bool, error) {
		return false, fmt.Errorf("pc %d %s: %s", pc, p.code[pc].op, fmt.Sprintf(format, a...))
	}
	pop := func() (avmValue, error) {
		if len(stack) == 0 {
			return avmValue{}, errors.New("stack underflow")
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
	push := func(v avmValue) error {
		if len(stack) >= avmMaxStack {
			return errors.New("stack overflow")
		}
		stack = append(stack, v)
		return nil
	}
	jump := func(label string) error {
		target, ok := p.labels[label]
		if !ok {
			return fmt.Errorf("unknown label %s", label)
		}
		pc = target - 1 // the loop increments
		return nil
	}
	imm := func(i int) (int, error) {
		in := p.code[pc]
		if i >= len(in.args) {
			return 0, errors.New("missing immediate")
		}
		n, err := strconv.Atoi(in.args[i])
		if err != nil || n < 0 {
			return 0, fmt.Errorf("bad immediate %q", in.args[i])
		}
		return n, nil
	}

	for pc = 0; pc < len(p.code); pc++ {
		if steps++; steps > avmMaxSteps {
			return fail("step limit")
		}
		in := p.code[pc]
		var err error
		switch in.op {
		case "pushint":
			var u uint64
			u, err = strconv.ParseUint(in.args[0], 0, 64)
			if err == nil {
				err = push(avmUint(u))
			}
		case "pushbytes":
			var b []byte
			b, err = hex.DecodeString(strings.TrimPrefix(in.args[0], "0x"))
			if err == nil {
				err = push(avmBytes(b))
			}
		case "load":
			var n int
			if n, err = imm(0); err == nil {
				if n > 255 {
					err = errors.New("scratch slot out of range")
				} else {
					err = push(scratch[n])
				}
			}
		case "store":
			var n int
			var v avmValue
			if n, err = imm(0); err == nil {
				if v, err = pop(); err == nil {
					scratch[n] = v
				}
			}
		case "txn":
			err = push(txnField(txn, in.args[0]))
		case "global":
			if in.args[0] != "ZeroAddress" {
				err = fmt.Errorf("unsupported global %s", in.args[0])
			} else {
				err = push(avmBytes(make([]byte, 32)))
			}
		case "arg":
			var n int
			if n, err = imm(0); err == nil {
				if n >= len(args) {
					err = errors.New("arg index out of range")
				} else {
					err = push(avmBytes(args[n]))
				}
			}
		case "assert":
			var u uint64
			if u, err = popUint(); err == nil && u == 0 {
				return false, nil
			}
		case "return":
			var u uint64
			u, err = popUint()
			return err == nil && u != 0, err
		case "b":
			err = jump(in.args[0])
		case "bz":
			var u uint64
			if u, err = popUint(); err == nil && u == 0 {
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
		case "swap":
			var a, b avmValue
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
			var a, b avmValue
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
		case "+", "-", "*", "/", "&", "<", "<=", "shl", "shr":
			var a, b uint64
			if b, err = popUint(); err == nil {
				if a, err = popUint(); err == nil {
					var r uint64
					r, err = uintOp(in.op, a, b)
					if err == nil {
						err = push(avmUint(r))
					}
				}
			}
		case "==", "!=":
			var a, b avmValue
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
						err = push(avmUint(boolUint(eq == (in.op == "=="))))
					}
				}
			}
		case "itob":
			var u uint64
			if u, err = popUint(); err == nil {
				err = push(avmBytes(binary.BigEndian.AppendUint64(nil, u)))
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
					err = push(avmUint(u))
				}
			}
		case "len":
			var b []byte
			if b, err = popBytes(); err == nil {
				err = push(avmUint(uint64(len(b))))
			}
		case "sha256":
			var b []byte
			if b, err = popBytes(); err == nil {
				sum := sha256.Sum256(b)
				err = push(avmBytes(sum[:]))
			}
		case "concat":
			var a, b []byte
			if b, err = popBytes(); err == nil {
				if a, err = popBytes(); err == nil {
					if len(a)+len(b) > avmMaxBytes {
						err = errors.New("concat result exceeds 4096 bytes")
					} else {
						err = push(avmBytes(append(append(make([]byte, 0, len(a)+len(b)), a...), b...)))
					}
				}
			}
		case "bzero":
			var n uint64
			if n, err = popUint(); err == nil {
				if n > avmMaxBytes {
					err = errors.New("bzero exceeds 4096 bytes")
				} else {
					err = push(avmBytes(make([]byte, n)))
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
							err = push(avmBytes(out))
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
						err = push(avmUint(uint64(a[i])))
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
							err = push(avmBytes(out))
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
							err = fmt.Errorf("no hook for %s", in.op)
						} else {
							err = push(avmUint(boolUint(verify(data, sig, key))))
						}
					}
				}
			}
		default:
			err = fmt.Errorf("unsupported opcode %q", in.op)
		}
		if err != nil {
			return fail("%v", err)
		}
	}
	// Falling off the end approves only with exactly one nonzero value left.
	if len(stack) == 1 && !stack[0].isBytes && stack[0].uint != 0 {
		return true, nil
	}
	return false, errAVMReject
}

func boolUint(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

func pushExtract(push func(avmValue) error, a []byte, s, l uint64, toEnd bool) error {
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
	return push(avmBytes(append([]byte(nil), a[s:end]...)))
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
	case "shl", "shr":
		if b >= 64 {
			return 0, fmt.Errorf("%s by %d", op, b)
		}
		if op == "shl" {
			return a << b, nil
		}
		return a >> b, nil
	}
	return 0, fmt.Errorf("unsupported operator %s", op)
}

func txnField(txn avmTxn, field string) avmValue {
	switch field {
	case "TxID":
		return avmBytes(txn.TxID)
	case "Sender":
		return avmBytes(txn.Sender)
	case "RekeyTo":
		return avmBytes(txn.RekeyTo)
	case "CloseRemainderTo":
		return avmBytes(txn.CloseRemainderTo)
	case "FirstValid":
		return avmUint(txn.FirstValid)
	case "LastValid":
		return avmUint(txn.LastValid)
	}
	// An unknown field panics the test run rather than reading as zero.
	panic("avmSim: unsupported txn field " + field)
}
