// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientenroll

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine/connect"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
)

type fakeEnrollmentClient struct {
	host           string
	port           int
	identityFile   string
	knownHostsPath string
	label          string
	approval       sshtunnel.HostKeyApprovalHandler
	progressCalled bool
	fingerprint    string
	pending        bool
	requestErr     error
}

func (f *fakeEnrollmentClient) RequestEnrollmentWithContext(
	_ context.Context,
	host string,
	port int,
	identityFile string,
	knownHostsPath string,
	label string,
	approval sshtunnel.HostKeyApprovalHandler,
	onEnrollmentStart func(string),
) (connect.EnrollmentResult, error) {
	f.host = host
	f.port = port
	f.identityFile = identityFile
	f.knownHostsPath = knownHostsPath
	f.label = label
	f.approval = approval
	if onEnrollmentStart != nil {
		onEnrollmentStart("SHA256:test-client")
		f.progressCalled = true
	}
	return connect.EnrollmentResult{Fingerprint: f.fingerprint, Pending: f.pending}, f.requestErr
}

func TestRequestEndpointEnrollmentResolvesEndpointScope(t *testing.T) {
	dataDir := t.TempDir()
	client := &fakeEnrollmentClient{fingerprint: "SHA256:test-client", pending: true}
	approval := func(string, string) (bool, error) { return true, nil }
	result, err := RequestEndpointEnrollment(
		context.Background(),
		client,
		"east",
		config.ClientEndpointConfig{
			Role:           config.ClientEndpointRoleCosigner,
			URL:            "ssh://cosigner.example:2222",
			IdentityFile:   filepath.Join(dataDir, ".ssh", "id_ed25519"),
			KnownHostsPath: filepath.Join(dataDir, ".ssh", "known_hosts"),
		},
		"laptop",
		approval,
		func(string) {},
	)
	if err != nil {
		t.Fatalf("RequestEndpointEnrollment() error = %v", err)
	}
	if result.Alias != "east" || result.Fingerprint != "SHA256:test-client" || !result.Pending {
		t.Fatalf("result = %+v", result)
	}
	if client.host != "cosigner.example" || client.port != 2222 || client.label != "laptop" {
		t.Fatalf("request target = %s:%d label %q", client.host, client.port, client.label)
	}
	if client.identityFile != filepath.Join(dataDir, ".ssh", "id_ed25519") || client.knownHostsPath != filepath.Join(dataDir, ".ssh", "known_hosts") {
		t.Fatalf("identity %q known_hosts %q", client.identityFile, client.knownHostsPath)
	}
	if client.approval == nil || !client.progressCalled {
		t.Fatal("interactive callbacks were not forwarded")
	}
}

func TestRequestEndpointEnrollmentReportsFailure(t *testing.T) {
	client := &fakeEnrollmentClient{requestErr: errors.New("denied")}
	_, err := RequestEndpointEnrollment(
		context.Background(), client, "east",
		config.ClientEndpointConfig{Role: config.ClientEndpointRoleCosigner, URL: "ssh://cosigner.example"},
		"", nil, nil,
	)
	if err == nil || !errors.Is(err, client.requestErr) {
		t.Fatalf("RequestEndpointEnrollment() error = %v, want the client failure", err)
	}
}

func TestRequestEndpointEnrollmentRequiresClientAndAlias(t *testing.T) {
	endpoint := config.ClientEndpointConfig{Role: config.ClientEndpointRoleCosigner, URL: "ssh://cosigner.example"}
	if _, err := RequestEndpointEnrollment(context.Background(), nil, "east", endpoint, "", nil, nil); err == nil {
		t.Fatal("nil client error = nil")
	}
	if _, err := RequestEndpointEnrollment(context.Background(), &fakeEnrollmentClient{}, "", endpoint, "", nil, nil); err == nil {
		t.Fatal("empty alias error = nil")
	}
}
