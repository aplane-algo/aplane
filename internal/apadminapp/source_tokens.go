// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apadminapp

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/termsafe"
)

const sourceTokenUsage = "usage: apadmin source token <set SELECTOR SOURCE [--token-stdin] | remove SELECTOR SOURCE | list [SELECTOR]>"

// tokenStdinFlag reads the token from stdin instead of prompting for it. A
// token is never a command-line argument, which would put it in the process
// list.
const tokenStdinFlag = "--token-stdin"

// maxTokenInput bounds what --token-stdin reads. The signer refuses a token
// over 1024 bytes; this only keeps a wrong file from being read whole.
const maxTokenInput = 4096

// sourceTokenRemoveNotice follows every successful remove.
const sourceTokenRemoveNotice = "Removing a token does not revoke it: generations made while it was set keep a copy until they are pruned, and backups made while it was set keep one, so revoke the token at the service."

type sourceTokenCommand struct {
	verb       string
	selector   string
	source     string
	tokenStdin bool
}

// parseSource parses a source token command. Each needs an unlocked signer,
// whose keyring opens the token files.
func parseSource(args []string) (catalogCommand, error) {
	cmd, err := parseSourceTokenCommand(args)
	if err != nil {
		return catalogCommand{}, err
	}
	parsed := unlockedCommand(func(c Catalog) error { return c.runSourceToken(cmd) })
	parsed.readsStdin = cmd.tokenStdin
	return parsed, nil
}

func parseSourceTokenCommand(args []string) (sourceTokenCommand, error) {
	if len(args) < 2 || args[0] != "token" {
		return sourceTokenCommand{}, errors.New(sourceTokenUsage)
	}
	cmd := sourceTokenCommand{verb: args[1]}
	var operands []string
	for _, arg := range args[2:] {
		if arg == tokenStdinFlag && cmd.verb == "set" && !cmd.tokenStdin {
			cmd.tokenStdin = true
			continue
		}
		if strings.HasPrefix(arg, "-") {
			return sourceTokenCommand{}, errors.New(sourceTokenUsage)
		}
		operands = append(operands, arg)
	}
	switch {
	case cmd.verb == "list" && len(operands) <= 1:
		if len(operands) == 1 {
			cmd.selector = operands[0]
		}
	case (cmd.verb == "set" || cmd.verb == "remove") && len(operands) == 2:
		cmd.selector, cmd.source = operands[0], operands[1]
	default:
		return sourceTokenCommand{}, errors.New(sourceTokenUsage)
	}
	return cmd, nil
}

func (c Catalog) runSourceToken(cmd sourceTokenCommand) error {
	switch cmd.verb {
	case "set":
		return c.setSourceToken(cmd)
	case "remove":
		return c.removeSourceToken(cmd)
	default:
		return c.listSourceTokens(cmd.selector)
	}
}

func (c Catalog) setSourceToken(cmd sourceTokenCommand) error {
	var token []byte
	var err error
	if cmd.tokenStdin {
		token, err = readTokenInput(c.Streams.Stdin)
	} else {
		token, err = c.ReadSecret(fmt.Sprintf("Enter the token for source %s: ", termsafe.Line(cmd.source)))
	}
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(token)
	var result protocol.SourceTokenChangeResultMessage
	if err := c.Client.Request(protocol.SourceTokenSetMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeSourceTokenSet, ID: c.requestID("source-token-set")},
		Selector:    cmd.selector, Source: cmd.source, Token: protocol.SensitiveBytes(token),
	}, &result); err != nil {
		return err
	}
	if !result.Success {
		return resultError("source token set failed", result.Code, result.Error)
	}
	c.info("token set for source %s on %s", cmd.source, cmd.selector)
	for _, row := range result.Tokens {
		if row.Source == cmd.source && row.State == protocol.SourceTokenUnused {
			c.warn("no source %s of the policy document for %s takes a token, so this token is unused", cmd.source, cmd.selector)
		}
	}
	return nil
}

func (c Catalog) removeSourceToken(cmd sourceTokenCommand) error {
	var result protocol.SourceTokenChangeResultMessage
	if err := c.Client.Request(protocol.SourceTokenRemoveMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeSourceTokenRemove, ID: c.requestID("source-token-remove")},
		Selector:    cmd.selector, Source: cmd.source,
	}, &result); err != nil {
		return err
	}
	if !result.Success {
		return resultError("source token remove failed", result.Code, result.Error)
	}
	c.info("token removed for source %s on %s", cmd.source, cmd.selector)
	c.info("%s", sourceTokenRemoveNotice)
	return nil
}

// listSourceTokens lists one selector, or every selector a page at a time,
// as an export reads them.
func (c Catalog) listSourceTokens(selector string) error {
	var listings []protocol.SourceTokenSelector
	var pages sourceTokenPages
	for after := ""; ; {
		var result protocol.SourceTokenListResultMessage
		if err := c.Client.Request(protocol.SourceTokenListMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeSourceTokenList, ID: c.requestID("source-token-list")},
			Selector:    selector,
			After:       after,
		}, &result); err != nil {
			return err
		}
		if !result.Success {
			return resultError("source token list failed", result.Code, result.Error)
		}
		next, done, err := pages.next(result)
		if err != nil {
			return err
		}
		listings = append(listings, result.Selectors...)
		if done {
			break
		}
		after = next
	}
	rows := [][]string{{"SELECTOR", "SOURCE", "SET", "STATE"}}
	for _, listing := range listings {
		if listing.Selector == selector && listing.Policy == protocol.SourceTokenPolicyDefault {
			c.info("%s follows the node default, whose checks use the tokens of default", selector)
		}
		for _, token := range listing.Tokens {
			set := token.SetAt
			if set == "" {
				set = "-"
			}
			rows = append(rows, []string{listing.Selector, token.Source, set, sourceTokenStateLabel(token.State)})
		}
	}
	if len(rows) == 1 {
		c.info("no source tokens are set or needed")
	} else {
		writeTable(c.Streams.Stdout, rows)
	}
	return nil
}

func sourceTokenStateLabel(state string) string {
	switch state {
	case protocol.SourceTokenInUse:
		return "in use"
	case protocol.SourceTokenUnused:
		return "unused"
	case protocol.SourceTokenNeeded:
		return "needed"
	}
	return state
}

// writeTable prints rows in columns two spaces apart. Every cell can hold
// text the daemon sent, so each is escaped for one terminal line first.
func writeTable(w io.Writer, rows [][]string) {
	var widths []int
	for _, row := range rows {
		for i, cell := range row {
			row[i] = termsafe.Line(cell)
			if i == len(widths) {
				widths = append(widths, 0)
			}
			widths[i] = max(widths[i], len(row[i]))
		}
	}
	for _, row := range rows {
		var line strings.Builder
		for i, cell := range row {
			if i == len(row)-1 {
				line.WriteString(cell)
				break
			}
			fmt.Fprintf(&line, "%-*s  ", widths[i], cell)
		}
		_, _ = fmt.Fprintln(w, line.String())
	}
}

// readTokenInput reads a token from r, up to maxTokenInput bytes, with one
// trailing line break removed. It reads into one buffer it never grows, so
// zeroing what it returns clears the only copy it made.
func readTokenInput(r io.Reader) ([]byte, error) {
	buf := make([]byte, maxTokenInput+1)
	n := 0
	for n < len(buf) {
		read, err := r.Read(buf[n:])
		n += read
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			crypto.ZeroBytes(buf)
			return nil, fmt.Errorf("read the token from stdin: %w", err)
		}
	}
	if n > maxTokenInput {
		crypto.ZeroBytes(buf)
		return nil, fmt.Errorf("the token on stdin is longer than %d bytes", maxTokenInput)
	}
	token := buf[:n]
	if strings.HasSuffix(string(token), "\n") {
		token = token[:len(token)-1]
		if strings.HasSuffix(string(token), "\r") {
			token = token[:len(token)-1]
		}
	}
	crypto.ZeroBytes(buf[len(token):])
	if len(token) == 0 {
		return nil, errors.New("no token on stdin")
	}
	return token, nil
}
