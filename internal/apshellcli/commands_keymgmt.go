// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

// Key management commands: generate, delete

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/cmdspec"
	"github.com/aplane-algo/aplane/internal/keytypefmt"
)

func (r *REPLState) cmdGenerate(args []string, _ interface{}) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: generate <key_type> [param=value ...]")
	}

	keyType := args[0]
	positional, params, err := cmdspec.ParseKeyValueArgs(args[1:])
	if err != nil {
		return err
	}
	if len(positional) > 0 {
		return fmt.Errorf("invalid parameter %q (expected param=value)", positional[0])
	}

	result, err := r.app().GenerateKey(r.commandContext(), apshellapp.GenerateKeyRequest{
		KeyType: keyType,
		Params:  params,
	})
	if err != nil {
		return err
	}

	r.printf("Generated %s key: %s\n", keytypefmt.Display(result.KeyType), result.Address)

	return nil
}

func (r *REPLState) cmdDelete(args []string, _ interface{}) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: delete <address>")
	}

	target, err := r.app().ResolveDeleteKeyTarget(r.commandContext(), apshellapp.DeleteKeyRequest{Address: args[0]})
	if err != nil {
		return err
	}

	if !r.AutoConfirm {
		response, err := r.readDeleteKeyResponse(target.Address)
		if err != nil {
			return err
		}
		if response != "y" && response != "yes" {
			r.println("Cancelled.")
			return nil
		}
	}

	if err := r.app().DeleteKey(r.commandContext(), apshellapp.DeleteKeyRequest{Address: args[0]}); err != nil {
		return err
	}

	r.println("Key deleted.")

	return nil
}
