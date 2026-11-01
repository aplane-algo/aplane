// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apadminapp

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/aplane-algo/aplane/internal/protocol"
)

const asaUsage = "usage: apadmin asa <list | add NETWORK ASSET-ID [--yes] | remove NETWORK ASSET-ID | remove --genesis HASH ASSET-ID>"

// asaCommandAuth validates an asa command. Every asa command reads the
// node's policy state, so each unlocks.
func asaCommandAuth(args []string) (AuthMode, error) {
	if _, err := parseASACommand(args); err != nil {
		return AuthUnlock, err
	}
	return AuthUnlock, nil
}

type asaCommand struct {
	verb    string
	network string
	genesis string
	assetID uint64
	yes     bool
}

func parseASACommand(args []string) (asaCommand, error) {
	if len(args) == 0 {
		return asaCommand{}, errors.New(asaUsage)
	}
	cmd := asaCommand{verb: args[0]}
	rest := args[1:]
	switch cmd.verb {
	case "list":
		if len(rest) != 0 {
			return asaCommand{}, errors.New(asaUsage)
		}
		return cmd, nil
	case "add":
		if len(rest) == 3 && rest[2] == "--yes" {
			cmd.yes, rest = true, rest[:2]
		}
	case "remove":
		if len(rest) == 3 && rest[0] == "--genesis" {
			cmd.genesis, rest = rest[1], rest[1:]
		}
	default:
		return asaCommand{}, errors.New(asaUsage)
	}
	if len(rest) != 2 {
		return asaCommand{}, errors.New(asaUsage)
	}
	if cmd.genesis == "" {
		if strings.HasPrefix(rest[0], "-") {
			return asaCommand{}, errors.New(asaUsage)
		}
		cmd.network = rest[0]
	}
	id, err := strconv.ParseUint(rest[1], 10, 64)
	if err != nil || id == 0 {
		return asaCommand{}, fmt.Errorf("asset ID %q must be a positive whole number", rest[1])
	}
	cmd.assetID = id
	return cmd, nil
}

func (c Catalog) runASA(args []string) error {
	cmd, err := parseASACommand(args)
	if err != nil {
		return err
	}
	switch cmd.verb {
	case "list":
		return c.listASASet()
	case "add":
		return c.addASA(cmd)
	default:
		return c.removeASA(cmd)
	}
}

func (c Catalog) listASASet() error {
	var result protocol.ASASetMessage
	if err := c.Client.Request(protocol.ListASASetMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeListASASet, ID: c.requestID("asa-list")},
	}, &result); err != nil {
		return err
	}
	if result.Error != "" {
		return resultError("asa list failed", result.Code, result.Error)
	}
	operator := 0
	for _, a := range result.Assets {
		if a.Origin == "operator" {
			operator++
		}
	}
	c.info("%d asset(s): %d built in, %d confirmed on this node", len(result.Assets), len(result.Assets)-operator, operator)
	for _, a := range result.Assets {
		network := a.Network
		if network == "" {
			network = "(inactive: chain " + a.GenesisHash + ")"
		}
		line := fmt.Sprintf("  %-12s %-10d %-8s %d decimals  %s", network, a.AssetID, safeLabel(a.UnitName), a.Decimals, a.Origin)
		if a.Origin == "operator" {
			line += "  confirmed " + a.ConfirmedAt
		}
		if a.Shadowed {
			line += "  (now built in; the built-in entry is used)"
		}
		_, _ = fmt.Fprintln(c.Streams.Stdout, line)
	}
	return nil
}

func (c Catalog) addASA(cmd asaCommand) error {
	var looked protocol.LookupASAResultMessage
	if err := c.Client.Request(protocol.LookupASAMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeLookupASA, ID: c.requestID("asa-lookup")},
		Network:     cmd.network, AssetID: cmd.assetID,
	}, &looked); err != nil {
		return err
	}
	if !looked.Success {
		return resultError("asa lookup failed", looked.Code, looked.Error)
	}
	a := looked.Asset
	out := c.Streams.Stdout
	_, _ = fmt.Fprintf(out, "Asset %d on %s, as the node's algod reports it:\n", a.AssetID, a.Network)
	_, _ = fmt.Fprintf(out, "  chain (genesis hash)  %s\n", a.GenesisHash)
	_, _ = fmt.Fprintf(out, "  name                  %s\n", safeLabel(a.Name))
	_, _ = fmt.Fprintf(out, "  unit name             %s\n", safeLabel(a.UnitName))
	_, _ = fmt.Fprintf(out, "  decimals              %d\n", a.Decimals)
	_, _ = fmt.Fprintf(out, "  total                 %d base units\n", a.Total)
	_, _ = fmt.Fprintf(out, "  creator               %s\n", a.Creator)
	for _, role := range []struct{ label, addr string }{{"manager", a.Manager}, {"reserve", a.Reserve}, {"freeze", a.Freeze}, {"clawback", a.Clawback}} {
		value := role.addr
		if value == "" {
			value = "(none)"
		}
		_, _ = fmt.Fprintf(out, "  %-21s %s\n", role.label, value)
	}
	if a.Clawback != "" {
		_, _ = fmt.Fprintln(out, "  ! The clawback address can take this asset from any holder.")
	}
	if a.Freeze != "" {
		_, _ = fmt.Fprintln(out, "  ! The freeze address can freeze any holder's balance.")
	}
	if a.Manager != "" {
		_, _ = fmt.Fprintln(out, "  The manager can change the reserve, freeze and clawback addresses later; only the name, unit name and decimals are recorded.")
	}
	if !cmd.yes && !c.Confirm(fmt.Sprintf("Add asset %d (%s, %d decimals) to this node's ASA set? [y/N]: ", a.AssetID, safeLabel(a.UnitName), a.Decimals)) {
		c.info("not added")
		return nil
	}
	var result protocol.AddASAResultMessage
	if err := c.Client.Request(protocol.AddASAMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeAddASA, ID: c.requestID("asa-add")},
		Confirmed:   a,
	}, &result); err != nil {
		return err
	}
	if !result.Success {
		return resultError("asa add failed", result.Code, result.Error)
	}
	c.info("asset %d on %s added to the ASA set (generation %s)", a.AssetID, a.Network, result.GenerationID)
	return nil
}

func (c Catalog) removeASA(cmd asaCommand) error {
	var result protocol.RemoveASAResultMessage
	if err := c.Client.Request(protocol.RemoveASAMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeRemoveASA, ID: c.requestID("asa-remove")},
		Network:     cmd.network, GenesisHash: cmd.genesis, AssetID: cmd.assetID,
	}, &result); err != nil {
		return err
	}
	if !result.Success {
		for _, ref := range result.Blocking {
			_, _ = fmt.Fprintf(c.Streams.Stderr, "  referenced by %s at %s\n", ref.Document, ref.Pointer)
		}
		if result.BlockingOmitted > 0 {
			_, _ = fmt.Fprintf(c.Streams.Stderr, "  and %d more reference(s)\n", result.BlockingOmitted)
		}
		return resultError("asa remove failed", result.Code, result.Error)
	}
	c.info("asset %d removed from the ASA set (generation %s)", cmd.assetID, result.GenerationID)
	return nil
}

// safeLabel shows an issuer-chosen string without control characters, so a
// name cannot rewrite the terminal or hide the ID beside it.
func safeLabel(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			b.WriteString(fmt.Sprintf("\\u%04x", r))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
