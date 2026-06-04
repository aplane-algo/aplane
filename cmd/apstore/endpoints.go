// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/aplane-algo/aplane/internal/endpointrefs"
	apkeys "github.com/aplane-algo/aplane/internal/keys"
)

func cmdEndpoints(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: apstore endpoints <export>")
	}
	switch args[0] {
	case "export":
		return cmdEndpointsExport(args[1:])
	default:
		return fmt.Errorf("usage: apstore endpoints <export>")
	}
}

func cmdEndpointsExport(args []string) error {
	fs := flag.NewFlagSet("apstore endpoints export", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	alias := fs.String("alias", "", "endpoint alias")
	role := fs.String("role", "", "endpoint role: signing, attestation, or dual")
	endpointURL := fs.String("url", "", "endpoint URL")
	signerPort := fs.Int("signer-port", 0, "remote apsigner REST port")
	localPort := fs.Int("local-port", 0, "local tunnel port")
	outPath := fs.String("out", "", "output JSON path")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("usage: apstore endpoints export --alias <alias> --role signing|attestation|dual --url <url> [--signer-port <port>] [--local-port <port>] [--out endpoint.json]")
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: apstore endpoints export --alias <alias> --role signing|attestation|dual --url <url> [--signer-port <port>] [--local-port <port>] [--out endpoint.json]")
	}

	env := endpointrefs.Envelope{
		Kind:          endpointrefs.Kind,
		SchemaVersion: endpointrefs.SchemaVersion,
		Alias:         *alias,
		Role:          *role,
		URL:           *endpointURL,
		SignerPort:    *signerPort,
		LocalPort:     *localPort,
	}
	env, err := endpointrefs.Normalize(env)
	if err != nil {
		return err
	}
	keys, err := exportedAttestorPublicKeys(env.Role)
	if err != nil {
		return err
	}
	env.AttestorPublicKeys = keys
	data, err := endpointrefs.Marshal(env)
	if err != nil {
		return err
	}
	if strings.TrimSpace(*outPath) == "" {
		_, err := os.Stdout.Write(data)
		return err
	}
	if err := os.WriteFile(*outPath, data, 0o600); err != nil {
		return fmt.Errorf("failed to write endpoint envelope: %w", err)
	}
	logInfof("endpoint envelope written: %s", *outPath)
	return nil
}

func exportedAttestorPublicKeys(role string) ([]endpointrefs.AttestorPublicKey, error) {
	switch role {
	case endpointrefs.RoleSigning:
		return nil, nil
	case endpointrefs.RoleAttestation, endpointrefs.RoleDual:
	default:
		return nil, nil
	}

	records, err := listComponentPublicMetadata()
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("no public attestor component metadata found; regenerate the component key or run a future metadata backfill before exporting an attestation endpoint")
	}
	return records, nil
}

func listComponentPublicMetadata() ([]endpointrefs.AttestorPublicKey, error) {
	keysDir := keystorePaths().KeysDir(productIdentityID())
	entries, err := os.ReadDir(keysDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read keys directory: %w", err)
	}
	records := make([]endpointrefs.AttestorPublicKey, 0)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), apkeys.ComponentPublicMetadataSuffix) {
			continue
		}
		componentKey := strings.TrimSuffix(entry.Name(), apkeys.ComponentPublicMetadataSuffix)
		env, ok, err := apkeys.ReadComponentPublicMetadata(keystorePaths(), productIdentityID(), componentKey)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		records = append(records, endpointrefs.AttestorPublicKey{
			KeyType:      env.KeyType,
			PublicKeyHex: env.PublicKeyHex,
			ComponentKey: env.ComponentKey,
		})
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].ComponentKey < records[j].ComponentKey
	})
	return records, nil
}
