// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"testing"
)

// A single-valued option given twice is refused, naming the option, rather
// than read as its last value: `--pay 100000 ... pay=10000000` would send the
// larger payment, and a second `from` would sign from the second account.
func TestAppAndShellParsersRefuseRepeatedSingleValuedOptions(t *testing.T) {
	method := func(rest ...string) func() error {
		return func() error {
			_, err := parseMethodAppCallArgs(append([]string{"77", "deposit", "--abi", "c.json", "from", "alice"}, rest...))
			return err
		}
	}
	raw := func(rest ...string) func() error {
		return func() error {
			_, err := parseRawAppCallArgs(append([]string{"raw", "77", "from", "alice"}, rest...))
			return err
		}
	}
	deploy := func(rest ...string) func() error {
		return func() error {
			_, err := parseAppDeployArgs(append([]string{"from", "alice", "approval=a.teal", "clear=c.teal"}, rest...))
			return err
		}
	}
	tests := []struct {
		name  string
		parse func() error
		want  string
	}{
		{"app call --pay then pay=", method("--pay", "100000", "pay=10000000"), "pay given more than once"},
		{"app call pay= twice", method("pay=1", "pay=2"), "pay given more than once"},
		{"app call raw --pay twice", raw("--pay", "1", "--pay", "2"), "pay given more than once"},
		{"app call from twice", method("from", "treasury"), "from given more than once"},
		{"app call --abi then abi=", method("abi=other.json"), "abi given more than once"},
		{"app call --abi twice", method("--abi", "other.json"), "abi given more than once"},
		{"app call note twice", method("note=a", "note=b"), "note given more than once"},
		{"app call oncomp twice", method("oncomp=noop", "oncomp=delete"), "oncomp given more than once"},
		{"app call approval twice", method("oncomp=update", "approval=a.teal", "approval-bin=b.bin", "clear=c.teal"), "approval given more than once"},
		{"app call clear twice", raw("oncomp=update", "approval=a.teal", "clear-teal=c.teal", "clear=d.teal"), "clear given more than once"},
		{"app call fee twice", raw("fee=1000", "fee=2000"), "fee given more than once"},
		{"app call arg:preimage twice", method("arg:preimage=text:a", "arg:preimage=text:b"), "arg:preimage given more than once"},
		{"app deploy approval twice", deploy("approval-teal=b.teal"), "approval given more than once"},
		{"app deploy clear twice", deploy("clear-bin=d.bin"), "clear given more than once"},
		{"app deploy global-uint twice", deploy("global-uint=1", "global-uint=2"), "global-uint given more than once"},
		{"app deploy global-bytes twice", deploy("global-bytes=1", "global-bytes=2"), "global-bytes given more than once"},
		{"app deploy local-uint twice", deploy("local-uint=1", "local-uint=2"), "local-uint given more than once"},
		{"app deploy local-bytes twice", deploy("local-bytes=1", "local-bytes=2"), "local-bytes given more than once"},
		{"app deploy extra-pages twice", deploy("extra-pages=1", "extra-pages=2"), "extra-pages given more than once"},
		{"app deploy note twice", deploy("note=a", "note=b"), "note given more than once"},
		{"app deploy arg:preimage twice", deploy("arg:preimage=text:a", "arg:preimage=text:b"), "arg:preimage given more than once"},
		{"plugin arg:preimage twice", func() error {
			_, _, err := extractPluginLsigArgs([]string{"swap", "arg:preimage=text:a", "arg:preimage=text:b"})
			return err
		}, "arg:preimage given more than once"},
		{"validate arg:preimage twice", func() error {
			_, err := parseValidateLsigArgs([]string{"arg:preimage=text:a", "arg:preimage=text:b"})
			return err
		}, "arg:preimage given more than once"},
		{"rotate recover --stage twice", func() error {
			_, err := parseRotateRecover([]string{"vault", "--stage", "1", "--window", "2", "--stage", "3"})
			return err
		}, "--stage given more than once"},
		{"rotate recover --timeout twice", func() error {
			_, err := parseRotateRecover([]string{"vault", "--timeout", "1", "--timeout", "2"})
			return err
		}, "--timeout given more than once"},
		{"endpoints add --alias twice", func() error {
			_, err := parseEndpointsAddArgs([]string{"ssh://a.example", "--alias", "a", "--alias", "b"})
			return err
		}, "--alias given more than once"},
		{"endpoints add URL then --endpoint", func() error {
			_, err := parseEndpointsAddArgs([]string{"ssh://a.example", "--endpoint", "ssh://b.example", "--alias", "a"})
			return err
		}, "endpoint URL given more than once"},
		{"endpoints add --alias empty, then again", func() error {
			_, err := parseEndpointsAddArgs([]string{"ssh://a.example", "--alias", "", "--alias", "prod"})
			return err
		}, "--alias given more than once"},
		{"endpoints add --endpoint empty, then again", func() error {
			_, err := parseEndpointsAddArgs([]string{"--endpoint", "", "--endpoint", "ssh://b.example", "--alias", "a"})
			return err
		}, "endpoint URL given more than once"},
		{"endpoints add --endpoint empty, then a URL", func() error {
			_, err := parseEndpointsAddArgs([]string{"--endpoint", "", "ssh://b.example", "--alias", "a"})
			return err
		}, "usage: " + endpointsAddUsage},
		{"endpoints add --url twice", func() error {
			_, err := parseEndpointsAddArgs([]string{"--url", "ssh://a.example", "--url", "ssh://b.example", "--alias", "a"})
			return err
		}, "endpoint URL given more than once"},
		{"enroll --label twice", func() error {
			_, _, err := parseEnrollArgs([]string{"--label", "a", "-l", "b"})
			return err
		}, "--label given more than once"},
		{"enroll --endpoint twice", func() error {
			_, _, err := parseEnrollArgs([]string{"-e", "a", "--endpoint", "b"})
			return err
		}, "--endpoint given more than once"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.parse()
			if err == nil || err.Error() != tt.want {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

// The options that build lists still repeat: --arg (and arg=) for the
// method's arguments, account=, app=, asset= and box=, and arg: with
// different names.
func TestAppCallListOptionsStillRepeat(t *testing.T) {
	params, err := parseMethodAppCallArgs([]string{
		"77", "deposit", "--abi", "c.json", "from", "alice",
		"--arg", "1", "arg=2", "--arg", "3",
		"account=bob", "account=carol",
		"app=1", "app=2",
		"asset=1", "asset=2",
		"box=a", "box=b",
		"arg:preimage=text:p", "arg:hashlock=text:h",
		"nowait", "nowait",
	})
	if err != nil {
		t.Fatalf("parseMethodAppCallArgs() error = %v", err)
	}
	if len(params.ArgValues) != 3 || len(params.Accounts) != 2 || len(params.ForeignApps) != 2 ||
		len(params.AssetRefs) != 2 || len(params.Boxes) != 2 || len(params.LsigArgs) != 2 {
		t.Fatalf("list options parsed as %+v", params)
	}
	raw, err := parseRawAppCallArgs([]string{"raw", "77", "from", "alice", "arg-raw=text:a", "arg-raw=text:b"})
	if err != nil || len(raw.AppArgs) != 2 {
		t.Fatalf("parseRawAppCallArgs() = %+v, %v; want two app args", raw, err)
	}
}
