// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policycmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policyexport"
	"github.com/aplane-algo/aplane/internal/sourcetokens"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// Rescue unlocks the store, so it reads the token files' names and warns of
// a source the document takes a token for that its selector has none of.
func TestRescueCheckWarnsOfAMissingSourceToken(t *testing.T) {
	root, passphrase := initializedPolicyStore(t, noderole.RoleCosigner)
	t.Setenv(passphraseEnv, passphrase)

	active, kr, err := genstore.ResolveStoreRoot(storepaths.NewPaths(root), []byte(passphrase))
	if err != nil {
		t.Fatal(err)
	}
	f, err := sourcetokens.SetToken(nil, sourcetokens.DefaultSelector, "screening", []byte("tok-rescue"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	err = sourcetokens.WriteFile(active, f, kr)
	f.Zero()
	kr.Zero()
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join("..", "..", "..", "test", "contracts", "policy", "v1", "cosigner_key_external_checks.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	doc["key"] = policy.DefaultKey
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	file := writePolicyFile(t, "default.json", string(body))

	var stdout, stderr bytes.Buffer
	if err := (RescueRunner{}).Run(context.Background(), Command{Verb: VerbCheck, Args: []string{file}, DataDir: root},
		Streams{Stdout: &stdout, Stderr: &stderr}); err != nil || !strings.Contains(stdout.String(), "policy OK") {
		t.Fatalf("rescue check = %q, %q, %v", stdout.String(), stderr.String(), err)
	}
	warnings := stderr.String()
	if !strings.Contains(warnings, "/external_sources/treasury/token: source treasury takes a token and default has none set") {
		t.Fatalf("no missing-token warning for treasury:\n%s", warnings)
	}
	if strings.Contains(warnings, "source screening takes a token") {
		t.Fatalf("a warning for screening, whose token is set:\n%s", warnings)
	}
}

// A rescue export of a cosigner store records the token files' names, which
// rescue reads once it has unlocked the store.
func TestRescueExportRecordsSourceTokenNames(t *testing.T) {
	root, passphrase := initializedPolicyStore(t, noderole.RoleCosigner)
	t.Setenv(passphraseEnv, passphrase)
	active, kr, err := genstore.ResolveStoreRoot(storepaths.NewPaths(root), []byte(passphrase))
	if err != nil {
		t.Fatal(err)
	}
	f, err := sourcetokens.SetToken(nil, sourcetokens.DefaultSelector, "ops", []byte("tok-rescue"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	err = sourcetokens.WriteFile(active, f, kr)
	f.Zero()
	kr.Zero()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "export")
	if err := (RescueRunner{}).Run(context.Background(), Command{Verb: VerbExport, ExportDir: dir, DataDir: root},
		Streams{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}); err != nil {
		t.Fatal(err)
	}
	selected, err := policyexport.Discover([]string{filepath.Join(dir, policy.DefaultKey+".json")}, "")
	if err != nil || selected == nil {
		t.Fatalf("Discover() = %v, %v", selected, err)
	}
	if got := selected.Export.SourceTokens[policy.DefaultKey]; len(got) != 1 || got[0] != "ops" {
		t.Fatalf("recorded names = %v", selected.Export.SourceTokens)
	}
}
