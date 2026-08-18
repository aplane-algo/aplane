// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

// Key management commands: generate, delete

import (
	"fmt"
	"io"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/cmdspec"
	"github.com/aplane-algo/aplane/internal/command"
	"github.com/aplane-algo/aplane/internal/keytypefmt"
)

func (r *REPLState) cmdGenerate(args []string, _ interface{}) (command.Result, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("usage: generate <key_type> [param=value ...]")
	}

	keyType := args[0]
	positional, params, err := cmdspec.ParseKeyValueArgs(args[1:])
	if err != nil {
		return nil, err
	}
	if len(positional) > 0 {
		return nil, fmt.Errorf("invalid parameter %q (expected param=value)", positional[0])
	}

	result, err := r.app().GenerateKey(r.commandContext(), apshellapp.GenerateKeyRequest{
		KeyType: keyType,
		Params:  params,
	})
	if err != nil {
		return nil, err
	}
	return newShellCommandResult(func(w io.Writer) error {
		return r.withOutput(w, func() {
			r.printf("Generated %s key: %s\n", keytypefmt.Display(result.KeyType), result.Address)
		})
	}, generatedKeyProjection{KeyType: result.KeyType, Address: result.Address})
}

func (r *REPLState) cmdDelete(args []string, _ interface{}) (command.Result, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("usage: delete <address>")
	}

	target, err := r.app().ResolveDeleteKeyTarget(r.commandContext(), apshellapp.DeleteKeyRequest{Address: args[0]})
	if err != nil {
		return nil, err
	}

	if !r.AutoConfirm {
		response, err := r.readDeleteKeyResponse(target.Address)
		if err != nil {
			return nil, err
		}
		if response != "y" && response != "yes" {
			return newShellCommandResult(func(w io.Writer) error {
				_, err := fmt.Fprintln(w, "Cancelled.")
				return err
			}, deletedKeyProjection{Address: target.Address, Cancelled: true})
		}
	}

	if err := r.app().DeleteKey(r.commandContext(), apshellapp.DeleteKeyRequest{Address: args[0]}); err != nil {
		return nil, err
	}
	return newShellCommandResult(func(w io.Writer) error {
		_, err := fmt.Fprintln(w, "Key deleted.")
		return err
	}, deletedKeyProjection{Address: target.Address, Deleted: true})
}
