// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"testing"
)

// appTxnFields is what the program, note and fee options set on any app
// transaction request.
type appTxnFields struct {
	ApprovalPath     string
	ApprovalCompiled bool
	ClearPath        string
	ClearCompiled    bool
	Note             string
	Fee              uint64
	UseFlatFee       bool
}

// appTxnParser runs one app command's parser on its fixed prefix plus rest.
type appTxnParser struct {
	name    string
	unknown string
	parse   func(rest []string) (appTxnFields, error)
}

func appTxnParsers() []appTxnParser {
	return []appTxnParser{
		{"app call raw", "unknown app call argument: ", func(rest []string) (appTxnFields, error) {
			args := append([]string{"raw", "123", "from", "alice", "oncomp=update"}, rest...)
			p, err := parseRawAppCallArgs(args)
			if err != nil {
				return appTxnFields{}, err
			}
			return appTxnFields{p.ApprovalPath, p.ApprovalCompiled, p.ClearPath, p.ClearCompiled, p.Note, p.Fee, p.UseFlatFee}, nil
		}},
		{"app call method", "unknown app call argument: ", func(rest []string) (appTxnFields, error) {
			args := append([]string{"123", "increment", "abi=c.json", "from", "alice", "oncomp=update"}, rest...)
			p, err := parseMethodAppCallArgs(args)
			if err != nil {
				return appTxnFields{}, err
			}
			return appTxnFields{p.ApprovalPath, p.ApprovalCompiled, p.ClearPath, p.ClearCompiled, p.Note, p.Fee, p.UseFlatFee}, nil
		}},
		{"app deploy", "unknown app deploy argument: ", func(rest []string) (appTxnFields, error) {
			p, err := parseAppDeployArgs(deployArgs(rest...))
			if err != nil {
				return appTxnFields{}, err
			}
			return appTxnFields{p.ApprovalPath, p.ApprovalCompiled, p.ClearPath, p.ClearCompiled, p.Note, p.Fee, p.UseFlatFee}, nil
		}},
	}
}

// TestAppTxnOptionsParseAlikeAcrossCommands pins that app call, in both
// forms, and app deploy read the program, note and fee options the same way.
func TestAppTxnOptionsParseAlikeAcrossCommands(t *testing.T) {
	programs := []string{"approval=a.teal", "clear=c.teal"}
	with := func(rest ...string) []string { return append(append([]string{}, programs...), rest...) }
	base := appTxnFields{ApprovalPath: "a.teal", ClearPath: "c.teal"}

	accepts := []struct {
		name string
		args []string
		want appTxnFields
	}{
		{"programs by extension", []string{"approval=a.teal", "clear=c.bin"},
			appTxnFields{ApprovalPath: "a.teal", ClearPath: "c.bin", ClearCompiled: true}},
		{"explicit source forms", []string{"approval-teal=a.bin", "clear-teal=c.bin"},
			appTxnFields{ApprovalPath: "a.bin", ClearPath: "c.bin"}},
		{"explicit compiled forms", []string{"approval-bin=a.teal", "clear-bin=c.teal"},
			appTxnFields{ApprovalPath: "a.teal", ApprovalCompiled: true, ClearPath: "c.teal", ClearCompiled: true}},
		{"a value keeps its own equals signs", []string{"approval-teal=dir=x/a.teal", "clear=c.teal", "note=a=b"},
			appTxnFields{ApprovalPath: "dir=x/a.teal", ClearPath: "c.teal", Note: "a=b"}},
		{"a note", with("note=hello"), appTxnFields{ApprovalPath: "a.teal", ClearPath: "c.teal", Note: "hello"}},
		{"an empty note is a note", with("note="), base},
		{"a fee is a flat fee", with("fee=2000"),
			appTxnFields{ApprovalPath: "a.teal", ClearPath: "c.teal", Fee: 2000, UseFlatFee: true}},
		{"a zero fee is still a flat fee", with("fee=0"),
			appTxnFields{ApprovalPath: "a.teal", ClearPath: "c.teal", UseFlatFee: true}},
	}
	refusals := []struct {
		name string
		args []string
		want string // a want starting with ":" is appended to the parser's unknown-argument prefix
	}{
		{"approval without a value", []string{"approval="}, "missing value for approval"},
		{"approval-teal without a value", []string{"approval-teal="}, "missing value for approval"},
		{"approval-bin without a value", []string{"approval-bin="}, "missing value for approval"},
		{"clear without a value", []string{"clear="}, "missing value for clear"},
		{"clear-teal without a value", []string{"clear-teal="}, "missing value for clear"},
		{"clear-bin without a value", []string{"clear-bin="}, "missing value for clear"},
		{"approval twice across forms", []string{"approval-teal=a.teal", "approval-bin=a.bin"}, "approval given more than once"},
		{"clear twice across forms", []string{"clear=c.teal", "clear-teal=d.teal"}, "clear given more than once"},
		{"an empty program value before a repeat", []string{"approval=a.teal", "approval="}, "missing value for approval"},
		{"note twice", with("note=a", "note=b"), "note given more than once"},
		{"fee not a number", with("fee=1.5"), "invalid fee value: 1.5"},
		{"fee empty", with("fee="), "invalid fee value: "},
		{"fee negative", with("fee=-1"), "invalid fee value: -1"},
		{"fee twice", with("fee=1", "fee=2"), "fee given more than once"},
		{"fee repeated with a bad value", with("fee=1", "fee=x"), "fee given more than once"},
		{"option names are case sensitive", with("Fee=1"), ":Fee=1"},
		{"a longer name that starts like an option", with("fees=1"), ":fees=1"},
		{"a program option without its equals sign", with("approval-teal"), ":approval-teal"},
		{"a note without its equals sign", with("note"), ":note"},
	}

	for _, parser := range appTxnParsers() {
		for _, tt := range accepts {
			t.Run(parser.name+"/"+tt.name, func(t *testing.T) {
				got, err := parser.parse(tt.args)
				if err != nil {
					t.Fatalf("parse error = %v", err)
				}
				if got != tt.want {
					t.Fatalf("parse = %+v, want %+v", got, tt.want)
				}
			})
		}
		for _, tt := range refusals {
			t.Run(parser.name+"/"+tt.name, func(t *testing.T) {
				want := tt.want
				if want[0] == ':' {
					want = parser.unknown + want[1:]
				}
				got, err := parser.parse(tt.args)
				if err == nil || err.Error() != want {
					t.Fatalf("parse = %+v, %v; want error %q", got, err, want)
				}
			})
		}
	}
}
