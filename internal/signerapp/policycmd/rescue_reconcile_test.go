// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policycmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func rescueApply(t *testing.T, root string) (string, error) {
	t.Helper()
	file := writePolicyFile(t, "default.json", testSignerDoc)
	var stdout, stderr bytes.Buffer
	err := (RescueRunner{}).Run(context.Background(), Command{Verb: VerbApply, Args: []string{file}, DataDir: root, Yes: true},
		Streams{Stdout: &stdout, Stderr: &stderr})
	return stderr.String(), err
}

// Staging residue a crashed mint left does not block an offline apply: it
// reconciles first, as an unlock does, and says what it discarded.
func TestRescueApplyReconcilesStagingResidueFirst(t *testing.T) {
	root, passphrase := initializedPolicyStore(t, noderole.RoleSigner)
	t.Setenv(passphraseEnv, passphrase)
	residue := storepaths.GenerationStagingPrefix + "gen-1700000000-deadbeef"
	staging := filepath.Join(storepaths.NewPaths(root).GenerationsDir(), residue)
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	stderr, err := rescueApply(t, root)
	if err != nil {
		t.Fatalf("rescue apply with staging residue: %v", err)
	}
	if !strings.Contains(stderr, "reconciled: discarded crash residue "+residue) {
		t.Fatalf("stderr = %q, want the residue reported as discarded", stderr)
	}
	if _, err := os.Stat(staging); !os.IsNotExist(err) {
		t.Fatalf("staging residue after the apply: %v, want gone", err)
	}
	if doc := verifiedDefault(t, root, passphrase); string(doc.Bytes) != testSignerDoc {
		t.Fatalf("stored policy = %q, want the applied document", doc.Bytes)
	}
}

// An apply whose store root rename fails leaves its successor published and
// the current generation sealed. The rescue still hands a managed store back
// to its service principal, and the retry quarantines the successor first and
// commits.
func TestRescueApplyRetriesAfterAFailurePastPublication(t *testing.T) {
	root, passphrase := initializedPolicyStore(t, noderole.RoleSigner)
	t.Setenv(passphraseEnv, passphrase)
	calls := rootRescueHooks(t, true, nil)
	paths := storepaths.NewPaths(root)
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpRename && path == paths.StoreRootPath() {
			return errors.New("simulated store root rename failure")
		}
		return nil
	}
	t.Cleanup(func() { fsutil.TestHook = nil })
	_, err := rescueApply(t, root)
	fsutil.TestHook = nil
	if err == nil || !strings.Contains(err.Error(), "policy apply failed before commit") {
		t.Fatalf("rescue apply with a failing root rename = %v, want a failure before commit", err)
	}
	if len(*calls) != 1 || (*calls)[0] != (normalizeCall{dataDir: root, uid: 123, gid: 456}) {
		t.Fatalf("normalizations after the failed apply = %+v, want the managed store normalized once", *calls)
	}

	stderr, err := rescueApply(t, root)
	if err != nil {
		t.Fatalf("retried rescue apply: %v", err)
	}
	if !strings.Contains(stderr, "reconciled: quarantined uncommitted generation ") {
		t.Fatalf("stderr = %q, want the failed apply's successor reported as quarantined", stderr)
	}
	if doc := verifiedDefault(t, root, passphrase); string(doc.Bytes) != testSignerDoc {
		t.Fatalf("stored policy = %q, want the applied document", doc.Bytes)
	}
	if len(*calls) != 2 {
		t.Fatalf("normalizations = %+v, want one per mutating rescue", *calls)
	}
}
