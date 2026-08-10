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
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/protocol"
)

const endpointExportUsage = "usage: apstore endpoint export [--host <host> | --url <url>] [--signer-port <port>] [--local-port <port>] [--out endpoint.json]"

type endpointExportSettings struct {
	AdvertiseURL string
	SSHPort      int
	SignerPort   int
}

var endpointExportSettingsForCommand = loadEndpointExportSettings

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
	settings, err := endpointExportSettingsForCommand()
	if err != nil {
		return err
	}

	urlValue, err := endpointExportURL(*host, *endpointURL, settings.AdvertiseURL, endpointExportSSHPort(settings))
	if err != nil {
		return err
	}
	signerPortValue := *signerPort
	if signerPortValue == 0 && endpointExportUsesSSH(urlValue) {
		signerPortValue = endpointExportSignerPort(settings)
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
	if err := fsutil.WriteFileDurableWithProfile(*outPath, data, fsutil.PrivateStoreFileProfile); err != nil {
		return fmt.Errorf("failed to write endpoint envelope: %w", err)
	}
	logInfof("endpoint envelope written: %s", *outPath)
	return nil
}

func loadEndpointExportSettings() (endpointExportSettings, error) {
	client, err := newApstoreAdminClientForCommand()
	if err != nil {
		return endpointExportSettings{}, err
	}
	defer client.close()
	var settings protocol.AdminSettingsMessage
	if err := client.request(protocol.GetAdminSettingsMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeGetAdminSettings, ID: newApstoreRequestID("endpoint-export-settings")},
	}, &settings); err != nil {
		return endpointExportSettings{}, fmt.Errorf("load endpoint export settings: %w", err)
	}
	return endpointExportSettings{
		AdvertiseURL: settings.EndpointAdvertiseURL,
		SSHPort:      settings.SSHPort,
		SignerPort:   settings.SignerPort,
	}, nil
}

func endpointExportURL(host, explicitURL, advertisedURL string, sshPort int) (string, error) {
	explicitURL = strings.TrimSpace(explicitURL)
	if explicitURL != "" {
		return explicitURL, nil
	}
	host = strings.TrimSpace(host)
	if host != "" {
		if strings.Contains(host, "://") {
			return "", fmt.Errorf("--host must be a host or IP without a URL scheme; use --url for explicit endpoint URLs")
		}
		if _, _, err := net.SplitHostPort(host); err == nil {
			return "", fmt.Errorf("--host must not include a port; use --url for custom SSH ports")
		}
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
		}
		return "ssh://" + net.JoinHostPort(host, strconv.Itoa(sshPort)), nil
	}
	advertisedURL = strings.TrimSpace(advertisedURL)
	if advertisedURL != "" {
		return advertisedURL, nil
	}
	return "", fmt.Errorf("endpoint advertise_url is not configured; pass --host/--url or set endpoint.advertise_url in config.yaml")
}

func endpointExportUsesSSH(rawURL string) bool {
	return strings.HasPrefix(strings.TrimSpace(strings.ToLower(rawURL)), "ssh://")
}

func endpointExportSSHPort(settings endpointExportSettings) int {
	if settings.SSHPort != 0 {
		return settings.SSHPort
	}
	return apconfig.DefaultSSHPort
}

func endpointExportSignerPort(settings endpointExportSettings) int {
	if settings.SignerPort != 0 {
		return settings.SignerPort
	}
	return apconfig.DefaultRESTPort
}
