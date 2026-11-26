// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apadminapp

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/aplane-algo/aplane/internal/protocol"
)

const testToken = "tok-cli-5d2b"

func TestSourceTokenCommandsParse(t *testing.T) {
	for _, tt := range []struct {
		args       []string
		want       sourceTokenCommand
		readsStdin bool
	}{
		{[]string{"token", "set", "default", "screening"}, sourceTokenCommand{verb: "set", selector: "default", source: "screening"}, false},
		{[]string{"token", "set", "default", "screening", "--token-stdin"}, sourceTokenCommand{verb: "set", selector: "default", source: "screening", tokenStdin: true}, true},
		{[]string{"token", "set", "--token-stdin", "default", "screening"}, sourceTokenCommand{verb: "set", selector: "default", source: "screening", tokenStdin: true}, true},
		{[]string{"token", "remove", "KEY1", "ops"}, sourceTokenCommand{verb: "remove", selector: "KEY1", source: "ops"}, false},
		{[]string{"token", "list"}, sourceTokenCommand{verb: "list"}, false},
		{[]string{"token", "list", "KEY1"}, sourceTokenCommand{verb: "list", selector: "KEY1"}, false},
	} {
		got, err := parseSourceTokenCommand(tt.args)
		if err != nil || got != tt.want {
			t.Errorf("parse(%v) = %+v, %v; want %+v", tt.args, got, err, tt.want)
		}
		mode, err := CatalogAuthMode("source", tt.args)
		if err != nil || mode != AuthUnlock {
			t.Errorf("CatalogAuthMode(source %v) = %v, %v; want unlock", tt.args, mode, err)
		}
		if CatalogReadsStdin("source", tt.args) != tt.readsStdin {
			t.Errorf("CatalogReadsStdin(source %v) = %v", tt.args, !tt.readsStdin)
		}
	}
	for _, bad := range [][]string{
		nil,
		{"token"},
		{"tokens", "list"},
		{"token", "show", "default"},
		{"token", "set", "default"},
		{"token", "set", "default", "screening", testToken},
		{"token", "set", "default", "screening", "--token", testToken},
		{"token", "set", "default", "screening", "--token-stdin", "--token-stdin"},
		{"token", "remove", "default"},
		{"token", "remove", "default", "screening", "--token-stdin"},
		{"token", "list", "a", "b"},
	} {
		if _, err := CatalogAuthMode("source", bad); err == nil || !strings.Contains(err.Error(), "usage: apadmin source token") {
			t.Errorf("CatalogAuthMode(source %v) = %v, want the usage", bad, err)
		}
	}
}

func setRequester(t *testing.T, seen *[]byte, result protocol.SourceTokenChangeResultMessage) *fakeRequester {
	return &fakeRequester{handle: func(message, out any) error {
		request, ok := message.(protocol.SourceTokenSetMessage)
		if !ok {
			return fmt.Errorf("request = %T", message)
		}
		if request.Selector != "default" || request.Source != "screening" {
			return fmt.Errorf("request = %+v", request)
		}
		*seen = append([]byte(nil), request.Token...)
		*out.(*protocol.SourceTokenChangeResultMessage) = result
		return nil
	}}
}

// The prompt's token is sent once and zeroed after; nothing printed carries it.
func TestSourceTokenSetPromptsAndZeroes(t *testing.T) {
	var seen []byte
	var prompted []byte
	requester := setRequester(t, &seen, protocol.SourceTokenChangeResultMessage{
		Success: true, Tokens: []protocol.SourceTokenInfo{{Source: "screening", SetAt: "2026-11-21T01:00:00Z", State: protocol.SourceTokenInUse}},
	})
	var stdout, stderr bytes.Buffer
	var prompt string
	err := (Catalog{Client: requester, Streams: Streams{Stdout: &stdout, Stderr: &stderr}, ReadSecret: func(message string) ([]byte, error) {
		prompt = message
		prompted = []byte(testToken)
		return prompted, nil
	}}).Run("source", []string{"token", "set", "default", "screening"})
	if err != nil {
		t.Fatal(err)
	}
	if string(seen) != testToken || prompt != "Enter the token for source screening: " {
		t.Fatalf("sent %q after prompt %q", seen, prompt)
	}
	if !bytes.Equal(prompted, make([]byte, len(testToken))) {
		t.Fatal("the prompted token was not zeroed")
	}
	if out := stdout.String() + stderr.String(); strings.Contains(out, testToken) || !strings.Contains(out, "token set for source screening on default") {
		t.Fatalf("output = %q", out)
	}
}

func TestSourceTokenSetReadsStdin(t *testing.T) {
	for _, tt := range []struct{ input, want string }{
		{testToken, testToken},
		{testToken + "\n", testToken},
		{testToken + "\r\n", testToken},
	} {
		var seen []byte
		requester := setRequester(t, &seen, protocol.SourceTokenChangeResultMessage{Success: true})
		err := (Catalog{Client: requester, Streams: Streams{Stdin: iotest.OneByteReader(strings.NewReader(tt.input))}}).
			Run("source", []string{"token", "set", "default", "screening", "--token-stdin"})
		if err != nil || string(seen) != tt.want {
			t.Fatalf("stdin %q: sent %q, %v", tt.input, seen, err)
		}
	}
	for _, input := range []string{"", "\n", strings.Repeat("x", maxTokenInput+1)} {
		requester := &fakeRequester{}
		err := (Catalog{Client: requester, Streams: Streams{Stdin: strings.NewReader(input)}}).
			Run("source", []string{"token", "set", "default", "screening", "--token-stdin"})
		if err == nil || len(requester.requests) != 0 {
			t.Fatalf("stdin of %d bytes: %v, %d requests", len(input), err, len(requester.requests))
		}
	}
	requester := &fakeRequester{}
	err := (Catalog{Client: requester, Streams: Streams{Stdin: iotest.ErrReader(errors.New("broken pipe"))}}).
		Run("source", []string{"token", "set", "default", "screening", "--token-stdin"})
	if err == nil || !strings.Contains(err.Error(), "broken pipe") {
		t.Fatalf("a failed read = %v", err)
	}
}

func TestReadTokenInputZeroesTheBufferItDoesNotReturn(t *testing.T) {
	token, err := readTokenInput(strings.NewReader(testToken + "\r\n"))
	if err != nil || string(token) != testToken {
		t.Fatalf("readTokenInput = %q, %v", token, err)
	}
	whole := token[:cap(token)]
	if !bytes.Equal(whole[len(token):], make([]byte, len(whole)-len(token))) {
		t.Fatal("the buffer past the token is not zeroed")
	}
}

func TestSourceTokenSetWarnsWhenTheTokenIsUnused(t *testing.T) {
	var seen []byte
	requester := setRequester(t, &seen, protocol.SourceTokenChangeResultMessage{
		Success: true, Tokens: []protocol.SourceTokenInfo{{Source: "screening", SetAt: "2026-11-21T01:00:00Z", State: protocol.SourceTokenUnused}},
	})
	var stderr bytes.Buffer
	err := (Catalog{Client: requester, Streams: Streams{Stderr: &stderr}, ReadSecret: func(string) ([]byte, error) { return []byte(testToken), nil }}).
		Run("source", []string{"token", "set", "default", "screening"})
	if err != nil || !strings.Contains(stderr.String(), "warning: no source screening of the policy document for default takes a token, so this token is unused") {
		t.Fatalf("stderr = %q, %v", stderr.String(), err)
	}
}

func TestSourceTokenSetAndRemoveFailures(t *testing.T) {
	requester := &fakeRequester{handle: func(message, out any) error {
		*out.(*protocol.SourceTokenChangeResultMessage) = protocol.SourceTokenChangeResultMessage{Code: protocol.ErrCodeSourceTokenNotSet, Error: "no token is set for this source"}
		return nil
	}}
	err := (Catalog{Client: requester, ReadSecret: func(string) ([]byte, error) { return []byte(testToken), nil }}).
		Run("source", []string{"token", "remove", "default", "screening"})
	if err == nil || protocol.CodeForError(err) != protocol.ErrCodeSourceTokenNotSet || !strings.Contains(err.Error(), "source token remove failed: no token is set") {
		t.Fatalf("remove failure = %v", err)
	}
	if _, ok := requester.requests[0].(protocol.SourceTokenRemoveMessage); !ok {
		t.Fatalf("request = %T", requester.requests[0])
	}
	err = (Catalog{Client: requester, ReadSecret: func(string) ([]byte, error) { return nil, errors.New("token cannot be empty") }}).
		Run("source", []string{"token", "set", "default", "screening"})
	if err == nil || len(requester.requests) != 1 {
		t.Fatalf("a failed prompt = %v after %d requests", err, len(requester.requests))
	}
}

func TestSourceTokenRemoveSaysRemovingDoesNotRevoke(t *testing.T) {
	requester := &fakeRequester{handle: func(message, out any) error {
		*out.(*protocol.SourceTokenChangeResultMessage) = protocol.SourceTokenChangeResultMessage{Success: true}
		return nil
	}}
	var stderr bytes.Buffer
	if err := (Catalog{Client: requester, Streams: Streams{Stderr: &stderr}}).Run("source", []string{"token", "remove", "default", "screening"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "token removed for source screening on default\n"+sourceTokenRemoveNotice+"\n") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestSourceTokenListPrintsATable(t *testing.T) {
	requester := &fakeRequester{handle: func(message, out any) error {
		request := message.(protocol.SourceTokenListMessage)
		if request.Selector != "KEY1" {
			return fmt.Errorf("selector %q", request.Selector)
		}
		*out.(*protocol.SourceTokenListResultMessage) = protocol.SourceTokenListResultMessage{Success: true, Omitted: 0, Selectors: []protocol.SourceTokenSelector{
			{Selector: "KEY1", Policy: protocol.SourceTokenPolicyDefault, Tokens: []protocol.SourceTokenInfo{
				{Source: "old\x1b[2J", SetAt: "2026-11-20T09:00:00Z", State: protocol.SourceTokenUnused},
			}},
			{Selector: "default", Policy: protocol.SourceTokenPolicyOwn, Tokens: []protocol.SourceTokenInfo{
				{Source: "screening", SetAt: "2026-11-21T01:00:00Z", State: protocol.SourceTokenInUse},
				{Source: "treasury", State: protocol.SourceTokenNeeded},
			}},
		}}
		return nil
	}}
	var stdout, stderr bytes.Buffer
	if err := (Catalog{Client: requester, Streams: Streams{Stdout: &stdout, Stderr: &stderr}}).Run("source", []string{"token", "list", "KEY1"}); err != nil {
		t.Fatal(err)
	}
	want := "SELECTOR  SOURCE      SET                   STATE\n" +
		"KEY1      old\\x1b[2J  2026-11-20T09:00:00Z  unused\n" +
		"default   screening   2026-11-21T01:00:00Z  in use\n" +
		"default   treasury    -                     needed\n"
	if stdout.String() != want {
		t.Fatalf("table:\n%s\nwant:\n%s", stdout.String(), want)
	}
	if !strings.Contains(stderr.String(), "KEY1 follows the node default, whose checks use the tokens of default") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestSourceTokenListEmpty(t *testing.T) {
	requester := &fakeRequester{handle: func(message, out any) error {
		*out.(*protocol.SourceTokenListResultMessage) = protocol.SourceTokenListResultMessage{Success: true}
		return nil
	}}
	var stdout, stderr bytes.Buffer
	if err := (Catalog{Client: requester, Streams: Streams{Stdout: &stdout, Stderr: &stderr}}).Run("source", []string{"token", "list"}); err != nil {
		t.Fatal(err)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "no source tokens are set or needed") {
		t.Fatalf("stdout %q stderr %q", stdout.String(), stderr.String())
	}
}

// A listing of every selector is read a page at a time, each request
// starting after the last selector the one before listed, until a page
// leaves none out.
func TestSourceTokenListReadsEveryPage(t *testing.T) {
	pages := map[string]protocol.SourceTokenListResultMessage{
		"":        {Success: true, Omitted: 2, Selectors: []protocol.SourceTokenSelector{{Selector: "default", Tokens: []protocol.SourceTokenInfo{{Source: "ops", State: protocol.SourceTokenNeeded}}}}},
		"default": {Success: true, Omitted: 1, Selectors: []protocol.SourceTokenSelector{{Selector: "KEY1", Tokens: []protocol.SourceTokenInfo{{Source: "screening", SetAt: "2026-11-21T01:00:00Z", State: protocol.SourceTokenInUse}}}}},
		"KEY1":    {Success: true, Selectors: []protocol.SourceTokenSelector{{Selector: "KEY2", Tokens: []protocol.SourceTokenInfo{{Source: "treasury", SetAt: "2026-11-21T02:00:00Z", State: protocol.SourceTokenUnused}}}}},
	}
	requester := &fakeRequester{handle: func(message, out any) error {
		page, ok := pages[message.(protocol.SourceTokenListMessage).After]
		if !ok {
			return fmt.Errorf("after %q", message.(protocol.SourceTokenListMessage).After)
		}
		*out.(*protocol.SourceTokenListResultMessage) = page
		return nil
	}}
	var stdout, stderr bytes.Buffer
	if err := (Catalog{Client: requester, Streams: Streams{Stdout: &stdout, Stderr: &stderr}}).Run("source", []string{"token", "list"}); err != nil {
		t.Fatal(err)
	}
	want := "SELECTOR  SOURCE     SET                   STATE\n" +
		"default   ops        -                     needed\n" +
		"KEY1      screening  2026-11-21T01:00:00Z  in use\n" +
		"KEY2      treasury   2026-11-21T02:00:00Z  unused\n"
	if stdout.String() != want || len(requester.requests) != 3 || strings.Contains(stderr.String(), "not listed") {
		t.Fatalf("%d requests, table:\n%s\nstderr %q", len(requester.requests), stdout.String(), stderr.String())
	}
}

// A node whose listing does not move on is refused after one page per
// selector a cosigner can have, as the export's read is.
func TestSourceTokenListRefusesAListingThatDoesNotMoveOn(t *testing.T) {
	requester := &fakeRequester{handle: func(message, out any) error {
		*out.(*protocol.SourceTokenListResultMessage) = protocol.SourceTokenListResultMessage{Success: true, Omitted: 1,
			Selectors: []protocol.SourceTokenSelector{{Selector: "default"}}}
		return nil
	}}
	var stdout, stderr bytes.Buffer
	err := (Catalog{Client: requester, Streams: Streams{Stdout: &stdout, Stderr: &stderr}}).Run("source", []string{"token", "list"})
	if err == nil || !strings.Contains(err.Error(), "does not move on") || len(requester.requests) != 2 || stdout.Len() != 0 {
		t.Fatalf("Run() error = %v after %d requests, stdout %q", err, len(requester.requests), stdout.String())
	}
}
