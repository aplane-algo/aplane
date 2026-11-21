// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storevalidate_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keys/keystest"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/storevalidate"
	"github.com/aplane-algo/aplane/internal/sourcetokens"
	"github.com/aplane-algo/aplane/internal/storeinit"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/lsig/clientreg"
)

// A key the node does not hold.
const unheldKeyID = "AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPQ"

type tokenStore struct {
	root   string
	paths  storepaths.Paths
	active storepaths.GenPaths
	kr     *crypto.Keyring
	held   string // the Witness Key ID of the cosigner key the store holds
}

func newTokenStore(t *testing.T, role noderole.Role) tokenStore {
	t.Helper()
	clientreg.RegisterClient()
	root := t.TempDir()
	paths := storepaths.NewPaths(root)
	passphrase := []byte("storevalidate-test-passphrase")
	if _, err := storeinit.Initialize(passphrase, storeinit.Options{ValidateCandidate: storevalidate.FirstGeneration,
		DataDir: root, Paths: paths, Role: role,
	}); err != nil {
		t.Fatal(err)
	}
	active, kr, err := genstore.ResolveStoreRoot(paths, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(kr.Zero)
	s := tokenStore{root: root, paths: paths, active: active, kr: kr}
	if role == noderole.RoleCosigner {
		id, keyJSON := keystest.CosignerComponentFalcon1024KeyJSON(t, 0x5a)
		sealed, err := kr.Seal(keyJSON, crypto.CosignerCredentialContext(id))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keystest.CosignerCredentialFilePath(active, id), sealed, 0o600); err != nil {
			t.Fatal(err)
		}
		s.held = id
	}
	return s
}

func (s tokenStore) setToken(t *testing.T, selector string) {
	t.Helper()
	f, err := sourcetokens.SetToken(nil, selector, "screening", []byte("token-value"), time.Unix(1_785_200_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Zero()
	if err := sourcetokens.WriteFile(s.active, f, s.kr); err != nil {
		t.Fatal(err)
	}
}

func (s tokenStore) candidate(role noderole.Role) error {
	return storevalidate.Candidate(storevalidate.Options{
		Paths: s.paths, Candidate: s.active, Keyring: s.kr,
		ExpectedRole: role, DataDir: s.root, Config: &serverconfig.ServerConfig{},
	})
}

func TestCandidateValidatesSourceTokenFiles(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T, s tokenStore)
		wantErr string // empty when the candidate is valid
	}{
		{name: "no token files"},
		{name: "a held key's tokens", setup: func(t *testing.T, s tokenStore) { s.setToken(t, s.held) }},
		{name: "the default's tokens", setup: func(t *testing.T, s tokenStore) { s.setToken(t, sourcetokens.DefaultSelector) }},
		{
			name:    "tokens for a key the node does not hold",
			setup:   func(t *testing.T, s tokenStore) { s.setToken(t, unheldKeyID) },
			wantErr: "holds no cosigner key",
		},
		{
			name: "another key's file renamed to a held key's name",
			setup: func(t *testing.T, s tokenStore) {
				s.setToken(t, unheldKeyID)
				rename(t, s.active.SourceTokenPath(unheldKeyID), s.active.SourceTokenPath(s.held))
			},
			wantErr: "failed to decrypt",
		},
		{
			name: "a damaged file",
			setup: func(t *testing.T, s tokenStore) {
				if err := os.WriteFile(s.active.SourceTokenPath(s.held), []byte("damaged"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: "source tokens",
		},
		{
			name: "an oversize file",
			setup: func(t *testing.T, s tokenStore) {
				if err := os.WriteFile(s.active.SourceTokenPath(s.held), []byte(strings.Repeat(" ", sourcetokens.MaxFileBytes+1)), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: "exceeds size limit",
		},
		{
			name: "an archived token file",
			setup: func(t *testing.T, s tokenStore) {
				s.setToken(t, unheldKeyID)
				if err := sourcetokens.Archive(s.active, unheldKeyID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "an archived token file renamed to another key",
			setup: func(t *testing.T, s tokenStore) {
				s.setToken(t, unheldKeyID)
				if err := sourcetokens.Archive(s.active, unheldKeyID); err != nil {
					t.Fatal(err)
				}
				rename(t, s.active.DeletedSourceTokenPath(unheldKeyID), s.active.DeletedSourceTokenPath(s.held))
			},
			wantErr: "deleted archive",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTokenStore(t, noderole.RoleCosigner)
			if tt.setup != nil {
				tt.setup(t, s)
			}
			err := s.candidate(noderole.RoleCosigner)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("Candidate() error = %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("Candidate() error = %v, want one containing %q", err, tt.wantErr)
			case err != nil && strings.Contains(err.Error(), "token-value"):
				t.Fatalf("Candidate() error quotes a token: %v", err)
			}
		})
	}
}

// A token file on a signer node is a role conflict: the candidate fails
// closed, as with a role-forbidden key.
func TestCandidateRefusesSourceTokensOnASignerNode(t *testing.T) {
	s := newTokenStore(t, noderole.RoleSigner)
	if err := s.candidate(noderole.RoleSigner); err != nil {
		t.Fatalf("Candidate(signer, no token files) error = %v", err)
	}
	s.setToken(t, sourcetokens.DefaultSelector)
	err := s.candidate(noderole.RoleSigner)
	if err == nil || !strings.Contains(err.Error(), "node role inventory conflict") {
		t.Fatalf("Candidate(signer with a token file) error = %v, want a node role conflict", err)
	}
}

func rename(t *testing.T, from, to string) {
	t.Helper()
	if err := os.Rename(from, to); err != nil {
		t.Fatal(err)
	}
}
