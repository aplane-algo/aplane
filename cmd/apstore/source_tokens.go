// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"fmt"
	"os"

	"github.com/aplane-algo/aplane/internal/sourcetokens"
)

const sourceTokenDiscardUsage = "usage: apstore source token discard <selector> [--yes]"

// cmdSource repairs a selector's source token file while the daemon is
// stopped:
//
//	apstore source token discard <selector> [--yes]
//
// A token file that does not decrypt or decode fails every reload into
// recovery, and the daemon cannot remove a file it cannot read. Discard
// deletes it from the selected generation without reading it, as
// `apstore generations prune` deletes without the daemon; nothing is
// archived. Setting, removing and listing tokens are `apadmin source token`.
func cmdSource(args []string) error {
	if len(args) < 3 || args[0] != "token" || args[1] != "discard" {
		return usageErrorf("%s", sourceTokenDiscardUsage)
	}
	selector, assumeYes := args[2], false
	for _, arg := range args[3:] {
		if arg != "--yes" || assumeYes {
			return usageErrorf("%s", sourceTokenDiscardUsage)
		}
		assumeYes = true
	}
	if err := sourcetokens.ValidateSelector(selector); err != nil {
		return usageErrorf("%v; %s", err, sourceTokenDiscardUsage)
	}
	consequence := fmt.Sprintf("Discard deletes the source token file of %s without reading it, and archives nothing. "+
		"Every source that takes a token under %s then refuses with token_not_set until a token is set again with apadmin. "+
		"Generations and backups made while the tokens were set keep them; revoke a token at its service if it may have leaked.",
		selector, selector)
	if assumeYes {
		logInfof("%s Confirmed by --yes.", consequence)
	} else if !confirmYesNo(consequence + " Proceed? [y/N]: ") {
		return fmt.Errorf("discard cancelled")
	}
	logWarnf("discard has no durable audit log; capture terminal output externally if needed")

	active, kr, err := readStore()
	if err != nil {
		return err
	}
	defer kr.Zero()
	if _, err := os.Lstat(active.SourceTokenPath(selector)); os.IsNotExist(err) {
		logInfof("%s has no source token file; nothing to discard", selector)
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect the source token file of %s: %w", selector, err)
	}
	if err := sourcetokens.RemoveFile(active, selector); err != nil {
		return err
	}
	logInfof("discarded the source token file of %s", selector)

	// Say whether the next unlock can load the tokens that remain.
	role, err := storeNodeRole()
	if err != nil {
		return err
	}
	files, err := sourcetokens.LoadFiles(active, role, kr)
	for _, f := range files {
		f.Zero()
	}
	if err != nil {
		logWarnf("the remaining source token files still fail to load, so the next unlock still enters recovery: %v", err)
		return nil
	}
	logInfof("the remaining %d source token file(s) load", len(files))
	return nil
}
