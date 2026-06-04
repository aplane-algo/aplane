// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/endpointrefs"
)

const endpointExportUsage = "usage: apstore endpoint export (--host <host> | --url <url>) [--signer-port <port>] [--local-port <port>] [--out endpoint.json]"

func cmdEndpoint(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: apstore endpoint <export>")
	}
	switch args[0] {
	case "export":
		return cmdEndpointExport(args[1:])
	default:
		return fmt.Errorf("usage: apstore endpoint <export>")
	}
}

func cmdEndpointExport(args []string) error {
	fs := flag.NewFlagSet("apstore endpoint export", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	host := fs.String("host", "", "client-reachable SSH host or IP")
	endpointURL := fs.String("url", "", "endpoint URL")
	signerPort := fs.Int("signer-port", 0, "remote apsigner REST port")
	localPort := fs.Int("local-port", 0, "local tunnel port")
	outPath := fs.String("out", "", "output JSON path")
	if err := fs.Parse(args); err != nil {
		return errors.New(endpointExportUsage)
	}
	if fs.NArg() != 0 {
		return errors.New(endpointExportUsage)
	}

	urlValue, err := endpointExportURL(*host, *endpointURL)
	if err != nil {
		return err
	}
	signerPortValue := *signerPort
	if signerPortValue == 0 && endpointExportUsesSSH(urlValue) {
		signerPortValue = endpointExportSignerPort()
	}

	env := endpointrefs.Envelope{
		Schema:     endpointrefs.Schema,
		URL:        urlValue,
		SignerPort: signerPortValue,
		LocalPort:  *localPort,
	}
	env, err = endpointrefs.Normalize(env)
	if err != nil {
		return err
	}
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

func endpointExportURL(host, explicitURL string) (string, error) {
	explicitURL = strings.TrimSpace(explicitURL)
	if explicitURL != "" {
		return explicitURL, nil
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", errors.New(endpointExportUsage)
	}
	if strings.Contains(host, "://") {
		return "", fmt.Errorf("--host must be a host or IP without a URL scheme; use --url for explicit endpoint URLs")
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return "", fmt.Errorf("--host must not include a port; use --url for custom SSH ports")
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	}
	return "ssh://" + net.JoinHostPort(host, strconv.Itoa(endpointExportSSHPort())), nil
}

func endpointExportUsesSSH(rawURL string) bool {
	return strings.HasPrefix(strings.TrimSpace(strings.ToLower(rawURL)), "ssh://")
}

func endpointExportSSHPort() int {
	if config.SSH.Port != 0 {
		return config.SSH.Port
	}
	return apconfig.DefaultSSHPort
}

func endpointExportSignerPort() int {
	if config.SignerPort != 0 {
		return config.SignerPort
	}
	return apconfig.DefaultRESTPort
}
