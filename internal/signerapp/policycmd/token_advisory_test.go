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

// damagedTokenStore is a cosigner store whose node default token file no
// longer decrypts, as apstore source token discard is for.
func damagedTokenStore(t *testing.T) (string, string) {
	t.Helper()
	root, passphrase := initializedPolicyStore(t, noderole.RoleCosigner)
	t.Setenv(passphraseEnv, passphrase)
	active, kr, err := genstore.ResolveStoreRoot(storepaths.NewPaths(root), []byte(passphrase))
	if err != nil {
		t.Fatal(err)
	}
	kr.Zero()
	if err := os.WriteFile(active.SourceTokenPath(sourcetokens.DefaultSelector), []byte("not a token file"), 0o600); err != nil {
		t.Fatal(err)
	}
	return root, passphrase
}

// Rescue is for damaged stores, and token names only feed an advisory: a
// token file that cannot be read leaves the names not known, as on a locked
// node, and rescue says so in one line that names the selector and the
// command that removes the file. Status, check and export still work.
func TestRescueWorksOnAStoreWithADamagedTokenFile(t *testing.T) {
	root, _ := damagedTokenStore(t)
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
	note := "the source token file of default could not be read"

	var stdout, stderr bytes.Buffer
	if err := (RescueRunner{}).Run(context.Background(), Command{Verb: VerbStatus, DataDir: root},
		Streams{Stdout: &stdout, Stderr: &stderr}); err != nil || !strings.Contains(stdout.String(), "default") {
		t.Fatalf("rescue status = %q, %q, %v", stdout.String(), stderr.String(), err)
	}
	if strings.Count(stderr.String(), note) != 1 || !strings.Contains(stderr.String(), "apstore source token discard default") {
		t.Fatalf("rescue status stderr = %q, want one line naming default and the discard command", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if err := (RescueRunner{}).Run(context.Background(), Command{Verb: VerbCheck, Args: []string{file}, DataDir: root},
		Streams{Stdout: &stdout, Stderr: &stderr}); err != nil || !strings.Contains(stdout.String(), "policy OK") {
		t.Fatalf("rescue check = %q, %q, %v", stdout.String(), stderr.String(), err)
	}
	if strings.Contains(stderr.String(), "token_not_set") || strings.Contains(stderr.String(), "takes a token and") {
		t.Fatalf("a missing-token warning while the names are not known:\n%s", stderr.String())
	}
	if strings.Contains(stderr.String(), "not a token file") || strings.Contains(stderr.String(), "invalid character") {
		t.Fatalf("rescue quoted the damaged file:\n%s", stderr.String())
	}

	dir := filepath.Join(t.TempDir(), "export")
	if err := (RescueRunner{}).Run(context.Background(), Command{Verb: VerbExport, ExportDir: dir, DataDir: root},
		Streams{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}); err != nil {
		t.Fatalf("rescue export: %v", err)
	}
	selected, err := policyexport.Discover([]string{filepath.Join(dir, policy.DefaultKey+".json")}, "")
	if err != nil || selected == nil || selected.Export.SourceTokens != nil {
		t.Fatalf("an export without readable token files records no names: %+v, %v", selected, err)
	}
}

// Apply mints a generation, and a generation is admitted only with every
// token file whole, so a rescue apply is refused before anything is
// committed until the damaged file is discarded; rescue has said which file
// and how. The document is still checked first.
func TestRescueApplyNamesTheDamagedTokenFile(t *testing.T) {
	root, passphrase := damagedTokenStore(t)
	generation := func() string {
		t.Helper()
		selection, kr, err := genstore.OpenStoreRootSelection(storepaths.NewPaths(root), []byte(passphrase))
		if err != nil {
			t.Fatal(err)
		}
		kr.Zero()
		return selection.GenerationID()
	}
	before := generation()
	file := writePolicyFile(t, "default.json", testCosignerDoc(policy.DefaultKey))
	var stdout, stderr bytes.Buffer
	err := (RescueRunner{}).Run(context.Background(), Command{Verb: VerbApply, Args: []string{file}, DataDir: root, Yes: true},
		Streams{Stdout: &stdout, Stderr: &stderr})
	if err == nil || !strings.Contains(err.Error(), "before commit") || !strings.Contains(stdout.String(), "policy OK") {
		t.Fatalf("rescue apply = %v, %q; want the document checked, then refused before commit", err, stdout.String())
	}
	if !strings.Contains(stderr.String(), "apstore source token discard default") {
		t.Fatalf("stderr = %q, want the discard command", stderr.String())
	}
	if after := generation(); after != before {
		t.Fatalf("a refused apply committed generation %s", after)
	}
}

// An entry of source_tokens/ that is no token file cannot be discarded by
// selector, so rescue names the entry and says it is removed by hand.
func TestRescueNamesAnEntryThatIsNoTokenFile(t *testing.T) {
	root, passphrase := initializedPolicyStore(t, noderole.RoleCosigner)
	t.Setenv(passphraseEnv, passphrase)
	active, kr, err := genstore.ResolveStoreRoot(storepaths.NewPaths(root), []byte(passphrase))
	if err != nil {
		t.Fatal(err)
	}
	kr.Zero()
	if err := os.WriteFile(filepath.Join(active.SourceTokensDir(), "notes.txt"), []byte("not a token file"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := (RescueRunner{}).Run(context.Background(), Command{Verb: VerbStatus, DataDir: root},
		Streams{Stdout: &stdout, Stderr: &stderr}); err != nil {
		t.Fatalf("rescue status = %q, %q, %v", stdout.String(), stderr.String(), err)
	}
	note := stderr.String()
	if !strings.Contains(note, `"notes.txt"`) || !strings.Contains(note, "by hand") ||
		!strings.Contains(note, active.SourceTokensDir()) || strings.Contains(note, "apstore verify") ||
		strings.Contains(note, "not a token file") {
		t.Fatalf("rescue status stderr = %q, want the entry named and removed by hand", note)
	}
}
