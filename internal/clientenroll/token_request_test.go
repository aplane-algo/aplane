// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientenroll

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
)

type fakeTokenClient struct {
	host           string
	port           int
	identityFile   string
	knownHostsPath string
	approval       sshtunnel.HostKeyApprovalHandler
	progressCalled bool
	requestToken   string
	requestErr     error
	savedPath      string
	savedToken     string
	saveErr        error
}

func (f *fakeTokenClient) RequestTokenWithContext(
	_ context.Context,
	host string,
	port int,
	identityFile string,
	knownHostsPath string,
	approval sshtunnel.HostKeyApprovalHandler,
	progress func(),
) (string, error) {
	f.host = host
	f.port = port
	f.identityFile = identityFile
	f.knownHostsPath = knownHostsPath
	f.approval = approval
	if progress != nil {
		progress()
		f.progressCalled = true
	}
	return f.requestToken, f.requestErr
}

func (f *fakeTokenClient) SaveApshellTokenToPath(path, token string) (string, error) {
	f.savedPath = path
	f.savedToken = token
	return path, f.saveErr
}

func TestRequestEndpointTokenResolvesAndPersistsEndpointScope(t *testing.T) {
	dataDir := t.TempDir()
	client := &fakeTokenClient{requestToken: "secret-token"}
	approval := func(string, string) (bool, error) { return true, nil }
	result, err := RequestEndpointToken(
		context.Background(),
		client,
		dataDir,
		"east",
		config.ClientEndpointConfig{
			Role:           config.ClientEndpointRoleSentry,
			URL:            "ssh://sentry.example:2222",
			SignerPort:     9443,
			IdentityFile:   filepath.Join(dataDir, ".ssh", "id_ed25519"),
			KnownHostsPath: filepath.Join(dataDir, ".ssh", "known_hosts"),
			TokenFile:      filepath.Join(dataDir, "tokens", "east.token"),
		},
		approval,
		func() {},
	)
	if err != nil {
		t.Fatalf("RequestEndpointToken() error = %v", err)
	}
	if result.Alias != "east" || result.TokenPath != client.savedPath {
		t.Fatalf("result = %+v, saved path %q", result, client.savedPath)
	}
	if client.host != "sentry.example" || client.port != 2222 {
		t.Fatalf("request target = %s:%d", client.host, client.port)
	}
	if client.approval == nil || !client.progressCalled {
		t.Fatal("interactive callbacks were not forwarded")
	}
	if client.savedToken != "secret-token" {
		t.Fatalf("saved token = %q", client.savedToken)
	}
}

func TestRequestEndpointTokenDoesNotPersistFailedRequest(t *testing.T) {
	client := &fakeTokenClient{requestErr: errors.New("denied")}
	_, err := RequestEndpointToken(
		context.Background(), client, t.TempDir(), "east",
		config.ClientEndpointConfig{Role: config.ClientEndpointRoleSentry, URL: "ssh://sentry.example"},
		nil, nil,
	)
	if err == nil {
		t.Fatal("RequestEndpointToken() error = nil")
	}
	if client.savedPath != "" || client.savedToken != "" {
		t.Fatalf("failed request persisted token path=%q token=%q", client.savedPath, client.savedToken)
	}
}

func TestRequestEndpointTokenRequiresClientAndAlias(t *testing.T) {
	endpoint := config.ClientEndpointConfig{Role: config.ClientEndpointRoleSentry, URL: "https://sentry.example"}
	if _, err := RequestEndpointToken(context.Background(), nil, t.TempDir(), "east", endpoint, nil, nil); err == nil {
		t.Fatal("nil client error = nil")
	}
	if _, err := RequestEndpointToken(context.Background(), &fakeTokenClient{}, t.TempDir(), "", endpoint, nil, nil); err == nil {
		t.Fatal("empty alias error = nil")
	}
}
