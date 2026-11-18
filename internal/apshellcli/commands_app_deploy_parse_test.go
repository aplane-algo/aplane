// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"reflect"
	"testing"

	"github.com/aplane-algo/aplane/internal/cmdspec"
)

const appDeployUsage = "usage: app deploy from <account> approval=<path>|approval-teal=<path>|approval-bin=<path> clear=<path>|clear-teal=<path>|clear-bin=<path> global-uint=<n> global-bytes=<n> local-uint=<n> local-bytes=<n> [extra-pages=<n>] [note=<text>] [fee=<microalgos>] [nowait] [arg:[<account>:]<name>=<value>]"

// deployArgs is "from alice" followed by rest.
func deployArgs(rest ...string) []string {
	return append([]string{"from", "alice"}, rest...)
}

// lsigArgsFor is what cmdspec builds from tokens, and the error it stops at.
func lsigArgsFor(t *testing.T, tokens ...string) (cmdspec.LsigArgs, error) {
	t.Helper()
	var args cmdspec.LsigArgs
	for _, token := range tokens {
		if err := cmdspec.AddLsigArg(&args, token); err != nil {
			return args, err
		}
	}
	return args, nil
}

func TestParseAppDeployArgsAccepts(t *testing.T) {
	lsigArgs, err := lsigArgsFor(t, "arg:preimage=00ff", "arg:alice:note=aa")
	if err != nil {
		t.Fatal(err)
	}
	optionNamedLsigArgs, err := lsigArgsFor(t, "arg:fee=01", "arg:alice:approval=aa")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		args []string
		want appDeployArgs
	}{
		{"programs by extension", deployArgs("approval=a.teal", "clear=c.bin"),
			appDeployArgs{From: "alice", Wait: true, ApprovalPath: "a.teal", ClearPath: "c.bin", ClearCompiled: true}},
		{"extension case does not matter", deployArgs("approval=A.TEAL", "clear=c.Teal"),
			appDeployArgs{From: "alice", Wait: true, ApprovalPath: "A.TEAL", ClearPath: "c.Teal"}},
		{"explicit forms override the extension", deployArgs("approval-bin=a.teal", "clear-teal=c.bin"),
			appDeployArgs{From: "alice", Wait: true, ApprovalPath: "a.teal", ApprovalCompiled: true, ClearPath: "c.bin"}},
		{"a value keeps its own equals signs", deployArgs("approval-teal=dir=x/a.teal", "clear=c.teal", "note=a=b"),
			appDeployArgs{From: "alice", Wait: true, ApprovalPath: "dir=x/a.teal", ClearPath: "c.teal", Note: "a=b"}},
		{"an empty note is a note", deployArgs("approval=a.teal", "clear=c.teal", "note="),
			appDeployArgs{From: "alice", Wait: true, ApprovalPath: "a.teal", ClearPath: "c.teal"}},
		{"every option, in any order", deployArgs("nowait", "fee=2000", "extra-pages=3", "local-bytes=4", "local-uint=3",
			"global-bytes=2", "global-uint=1", "note=hello", "arg:preimage=00ff", "clear=c.teal", "approval=a.teal", "arg:alice:note=aa"),
			appDeployArgs{From: "alice", ApprovalPath: "a.teal", ClearPath: "c.teal", GlobalUint: 1, GlobalBytes: 2, LocalUint: 3,
				LocalBytes: 4, ExtraPages: 3, Note: "hello", Fee: 2000, UseFlatFee: true, LsigArgs: lsigArgs}},
		{"a zero fee is still a flat fee", deployArgs("approval=a.teal", "clear=c.teal", "fee=0"),
			appDeployArgs{From: "alice", Wait: true, ApprovalPath: "a.teal", ClearPath: "c.teal", UseFlatFee: true}},
		{"the largest extra-pages value", deployArgs("approval=a.teal", "clear=c.teal", "extra-pages=4294967295"),
			appDeployArgs{From: "alice", Wait: true, ApprovalPath: "a.teal", ClearPath: "c.teal", ExtraPages: 4294967295}},
		{"the other counts are 64-bit", deployArgs("approval=a.teal", "clear=c.teal", "global-uint=4294967296", "local-bytes=18446744073709551615"),
			appDeployArgs{From: "alice", Wait: true, ApprovalPath: "a.teal", ClearPath: "c.teal", GlobalUint: 4294967296, LocalBytes: 18446744073709551615}},
		{"nowait may repeat", deployArgs("approval=a.teal", "clear=c.teal", "nowait", "nowait"),
			appDeployArgs{From: "alice", ApprovalPath: "a.teal", ClearPath: "c.teal"}},
		{"only a .teal extension is source", deployArgs("approval=a", "clear=c.TEAL.bak"),
			appDeployArgs{From: "alice", Wait: true, ApprovalPath: "a", ApprovalCompiled: true, ClearPath: "c.TEAL.bak", ClearCompiled: true}},
		{"a LogicSig argument named like an option stays an argument", deployArgs("approval=a.teal", "clear=c.teal", "arg:fee=01", "arg:alice:approval=aa"),
			appDeployArgs{From: "alice", Wait: true, ApprovalPath: "a.teal", ClearPath: "c.teal", LsigArgs: optionNamedLsigArgs}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAppDeployArgs(tt.args)
			if err != nil {
				t.Fatalf("parseAppDeployArgs() error = %v", err)
			}
			if !reflect.DeepEqual(*got, tt.want) {
				t.Fatalf("parseAppDeployArgs() = %+v, want %+v", *got, tt.want)
			}
		})
	}
}

func TestParseAppDeployArgsRefusals(t *testing.T) {
	_, badLsigArg := lsigArgsFor(t, "arg:")
	_, repeatedLsigArg := lsigArgsFor(t, "arg:preimage=00", "arg:preimage=11")
	_, valuelessLsigArg := lsigArgsFor(t, "arg:preimage")
	if badLsigArg == nil || repeatedLsigArg == nil || valuelessLsigArg == nil {
		t.Fatal("the LogicSig argument fixtures must be refused by cmdspec")
	}
	programs := []string{"approval=a.teal", "clear=c.teal"}
	with := func(rest ...string) []string { return deployArgs(append(programs, rest...)...) }
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no arguments", nil, appDeployUsage},
		{"no account", []string{"from"}, appDeployUsage},
		{"empty account", []string{"from", ""}, appDeployUsage},
		{"not from", []string{"to", "alice"}, appDeployUsage},

		{"approval without a value", deployArgs("approval="), "missing value for approval"},
		{"approval-teal without a value", deployArgs("approval-teal="), "missing value for approval"},
		{"approval-bin without a value", deployArgs("approval-bin="), "missing value for approval"},
		{"clear without a value", deployArgs("clear="), "missing value for clear"},
		{"clear-teal without a value", deployArgs("clear-teal="), "missing value for clear"},
		{"clear-bin without a value", deployArgs("clear-bin="), "missing value for clear"},
		{"approval twice across forms", deployArgs("approval-teal=a.teal", "approval-bin=a.bin"), "approval given more than once"},
		{"clear twice across forms", deployArgs("clear=c.teal", "clear-teal=d.teal"), "clear given more than once"},
		{"an empty program value before a repeat", deployArgs("approval=a.teal", "approval="), "missing value for approval"},

		{"global-uint not a number", with("global-uint=x"), "invalid global-uint value: x"},
		{"global-bytes negative", with("global-bytes=-1"), "invalid global-bytes value: -1"},
		{"local-uint empty", with("local-uint="), "invalid local-uint value: "},
		{"local-bytes with a sign", with("local-bytes=+1"), "invalid local-bytes value: +1"},
		{"extra-pages past 32 bits", with("extra-pages=4294967296"), "invalid extra-pages value: 4294967296"},
		{"fee not a number", with("fee=1.5"), "invalid fee value: 1.5"},
		{"global-uint twice", with("global-uint=1", "global-uint=2"), "global-uint given more than once"},
		{"global-bytes twice", with("global-bytes=1", "global-bytes=2"), "global-bytes given more than once"},
		{"local-uint twice", with("local-uint=1", "local-uint=2"), "local-uint given more than once"},
		{"local-bytes twice", with("local-bytes=1", "local-bytes=2"), "local-bytes given more than once"},
		{"extra-pages twice", with("extra-pages=1", "extra-pages=2"), "extra-pages given more than once"},
		{"fee twice", with("fee=1", "fee=2"), "fee given more than once"},
		{"note twice", with("note=a", "note=b"), "note given more than once"},
		{"global-uint past 64 bits", with("global-uint=18446744073709551616"), "invalid global-uint value: 18446744073709551616"},
		{"extra-pages negative", with("extra-pages=-1"), "invalid extra-pages value: -1"},
		{"the same program spelling twice", deployArgs("approval=a.teal", "approval=b.teal"), "approval given more than once"},

		{"unknown word", with("bogus"), "unknown app deploy argument: bogus"},
		{"unknown option", with("bogus=1"), "unknown app deploy argument: bogus=1"},
		{"an option name without its equals sign", with("fee"), "unknown app deploy argument: fee"},
		{"nowait with a value", with("nowait=1"), "unknown app deploy argument: nowait=1"},
		{"option names are case sensitive", with("Fee=1"), "unknown app deploy argument: Fee=1"},
		{"a longer name that starts like an option", with("fees=1"), "unknown app deploy argument: fees=1"},
		{"an empty argument", with(""), "unknown app deploy argument: "},
		{"a value with no name", with("=x"), "unknown app deploy argument: =x"},
		{"a program option without its equals sign", with("approval-teal"), "unknown app deploy argument: approval-teal"},

		{"a malformed LogicSig argument", with("arg:"), badLsigArg.Error()},
		{"a repeated LogicSig argument", with("arg:preimage=00", "arg:preimage=11"), repeatedLsigArg.Error()},
		{"a LogicSig argument without a value", with("arg:preimage"), valuelessLsigArg.Error()},

		{"no approval program", deployArgs("clear=c.teal"), "missing approval program"},
		{"no clear program", deployArgs("approval=a.teal"), "missing clear program"},
		{"no programs at all", deployArgs(), "missing approval program"},
		{"the first bad argument reports", deployArgs("bogus", "fee=x"), "unknown app deploy argument: bogus"},
		{"a bad argument before a missing program", deployArgs("approval=a.teal", "fee=x"), "invalid fee value: x"},
	}
	// A repeat is reported before the repeated value is read, for every
	// numeric option.
	for _, name := range []string{"global-uint", "global-bytes", "local-uint", "local-bytes", "extra-pages", "fee"} {
		tests = append(tests, struct {
			name string
			args []string
			want string
		}{name + " repeated with a bad value", with(name+"=1", name+"=x"), name + " given more than once"})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAppDeployArgs(tt.args)
			if err == nil || err.Error() != tt.want {
				t.Fatalf("parseAppDeployArgs() = %+v, %v; want error %q", got, err, tt.want)
			}
		})
	}
}
