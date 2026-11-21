// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/signerapp/storevalidate"
	"github.com/aplane-algo/aplane/internal/signerapp/templaterepair"
)

const templateRepairUsage = "usage: apstore template repair [repin <key_type>...] [drop <key_type>...] [--confirm]"

// templateRepairRequest is a parsed apstore template repair command line:
// the action for each canonical key type, and whether to commit.
type templateRepairRequest struct {
	actions map[string]templaterepair.Action
	confirm bool
}

// parseTemplateCommand reads the arguments after "template". Dispatch runs
// it before it takes the store lock, so a malformed command line is a usage
// error even while a signer holds the store.
func parseTemplateCommand(args []string) (templateRepairRequest, error) {
	if len(args) == 0 || args[0] != "repair" {
		return templateRepairRequest{}, usageErrorf("%s", templateRepairUsage)
	}
	actions, confirm, err := parseTemplateRepairArgs(args[1:])
	return templateRepairRequest{actions: actions, confirm: confirm}, err
}

// cmdTemplateRepair repairs the template record defects that put a store
// into recovery at unlock, with apsigner stopped (docs/USER_KEYTYPES.md,
// "Repairing a template record").
//
//	apstore template repair                                   preview the defects
//	apstore template repair repin <kt>... drop <kt>...        preview the repair
//	apstore template repair repin <kt>... drop <kt>... --confirm
func cmdTemplateRepair(req templateRepairRequest) error {
	actions, confirm := req.actions, req.confirm
	current, kr, err := readStore()
	if err != nil {
		return err
	}
	defer kr.Zero()
	role, err := storeNodeRole()
	if err != nil {
		return err
	}
	opts := templaterepair.Options{
		Paths: keystorePaths(), Current: current, Keyring: kr,
		Role: role, DataDir: dataDirectory, Config: &config,
	}
	if confirm {
		return runTemplateRepair(opts, actions)
	}
	preview, err := templaterepair.Inspect(opts)
	if err != nil {
		return err
	}
	if err := printTemplateRepairPreview(os.Stdout, preview); err != nil {
		return err
	}
	if len(actions) == 0 {
		return nil
	}
	entries, err := preview.Plan(actions)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		logInfof("would %s %s (%s)", entry.Action, entry.KeyType, defectLabel(entry.Defect))
	}
	logInfof("nothing was changed; add --confirm to commit the repair")
	return nil
}

// parseTemplateRepairArgs reads each verb's key types, canonical, and
// --confirm. A key type is named once, under one verb.
func parseTemplateRepairArgs(args []string) (map[string]templaterepair.Action, bool, error) {
	actions := make(map[string]templaterepair.Action)
	confirm := false
	var verb templaterepair.Action
	verbs := make(map[templaterepair.Action]int)
	for _, arg := range args {
		switch arg {
		case "--confirm":
			if confirm {
				return nil, false, usageErrorf("duplicate --confirm; %s", templateRepairUsage)
			}
			confirm = true
		case string(templaterepair.ActionRepin), string(templaterepair.ActionDrop):
			verb = templaterepair.Action(arg)
			if _, seen := verbs[verb]; seen {
				return nil, false, usageErrorf("%s is given twice; %s", verb, templateRepairUsage)
			}
			verbs[verb] = 0
		default:
			if strings.HasPrefix(arg, "-") {
				return nil, false, usageErrorf("unknown template repair option %s; %s", arg, templateRepairUsage)
			}
			if verb == "" {
				return nil, false, usageErrorf("key type %s has no repin or drop before it; %s", arg, templateRepairUsage)
			}
			keyType, err := keytypestate.NormalizeKeyType(arg)
			if err != nil {
				return nil, false, usageErrorf("%v; %s", err, templateRepairUsage)
			}
			if _, named := actions[keyType]; named {
				return nil, false, usageErrorf("key type %s is named twice; %s", keyType, templateRepairUsage)
			}
			actions[keyType] = verb
			verbs[verb]++
		}
	}
	for verb, count := range verbs {
		if count == 0 {
			return nil, false, usageErrorf("%s names no key type; %s", verb, templateRepairUsage)
		}
	}
	if confirm && len(actions) == 0 {
		return nil, false, usageErrorf("--confirm needs the key types to repair; %s", templateRepairUsage)
	}
	return actions, confirm, nil
}

func runTemplateRepair(opts templaterepair.Options, actions map[string]templaterepair.Action) error {
	logWarnf("template repair runs without apsigner: no authorization or audit log; capture terminal output externally if needed")
	result, err := templaterepair.Repair(opts, actions)
	for _, quarantined := range result.Reconciled.Quarantined {
		logInfof("reconciled: quarantined uncommitted generation %s", quarantined.GenerationID)
	}
	for _, staging := range result.Reconciled.DiscardedStaging {
		logInfof("reconciled: discarded staging residue %s", staging)
	}
	if genstore.RootCommitUncertain(err) {
		return fmt.Errorf("%w; start apsigner and unlock it to check which generation it selects", err)
	}
	if err != nil {
		adviseRefusal(err)
		return err
	}
	logInfof("template repair committed generation %s over %s, which is kept", result.GenerationID, result.Parent)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "KEY TYPE\tDEFECT\tACTION\tKEYS\tCONFLICT"); err != nil {
		return err
	}
	for _, entry := range result.Entries {
		conflict := "-"
		if entry.Action == templaterepair.ActionRepin {
			conflict = strconv.Itoa(entry.ConflictAfterRepin)
		}
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\n",
			entry.KeyType, defectLabel(entry.Defect), entry.Action, entry.Keys, conflict); err != nil {
			return err
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	for _, entry := range result.Entries {
		if entry.Archived != "" {
			logInfof("%s: template archived to %s", entry.KeyType, entry.Archived)
		}
		if entry.Action == templaterepair.ActionDrop && entry.Keys > 0 {
			logWarnf("%s: its %d key(s) keep signing, but no new key of the type can be created until the template is imported again", entry.KeyType, entry.Keys)
		}
	}
	logInfof("start apsigner and unlock it")
	return nil
}

func printTemplateRepairPreview(w io.Writer, preview templaterepair.Preview) error {
	if len(preview.Defects) == 0 {
		logInfof("generation %s has no template record defects", preview.GenerationID)
		return nil
	}
	logInfof("generation %s has %d template record defect(s)", preview.GenerationID, len(preview.Defects))
	table := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(table, "KEY TYPE\tDEFECT\tACTIONS\tKEYS"); err != nil {
		return err
	}
	edits := false
	for _, defect := range preview.Defects {
		actions := string(templaterepair.ActionDrop)
		if defect.Allows(templaterepair.ActionRepin) {
			actions = string(templaterepair.ActionRepin) + " or " + string(templaterepair.ActionDrop)
			edits = true
		}
		if _, err := fmt.Fprintf(table, "%s\t%s\t%s\t%d\n",
			defect.KeyType, defectLabel(defect), actions, defect.Keys); err != nil {
			return err
		}
	}
	if err := table.Flush(); err != nil {
		return err
	}
	for _, defect := range preview.Defects {
		if defect.Allows(templaterepair.ActionRepin) {
			printExternalEditEvidence(defect)
		}
	}
	if edits {
		logInfof("repin keeps the stored template as it is now: use it only if you know why the record and the template differ, for example after a fingerprint-format change")
		logInfof("otherwise drop the record, start apsigner, and import the template again from a file you trust with `apadmin template import`")
	}
	if preview.ReconcilePending() {
		logInfof("reconciliation is pending: %d uncommitted generation(s) to quarantine and %d staging residue(s) to discard; a repair with --confirm reconciles first, as an unlock does",
			len(preview.Reconcile.Quarantined), len(preview.Reconcile.DiscardedStaging))
	}
	if preview.OtherDamage != nil {
		logWarnf("a repair is refused while the generation has other damage, which unlock also refuses: %v", preview.OtherDamage)
		logWarnf("%s", otherDamageAdvice)
		return nil
	}
	if preview.CommitBlocked != nil {
		logWarnf("a repair is refused: no generation can be committed over the current one: %v", preview.CommitBlocked)
		adviseRefusal(preview.CommitBlocked)
		return nil
	}
	logInfof("repair every defect in one run: apstore template repair repin <key_type>... drop <key_type>... --confirm")
	return nil
}

// printExternalEditEvidence states what the store shows about an external
// edit. The key files are authenticated and the record is not, so keys that
// agree with the stored template point at the record, and keys that do not
// point at the template.
func printExternalEditEvidence(defect templaterepair.Defect) {
	logInfof("%s: the record pins %s; its stored template computes %s",
		defect.KeyType, displayValue(defect.RecordedFingerprint), defect.TemplateFingerprint)
	if defect.ConflictAfterRepin > 0 {
		logWarnf("%s: %d of its %d key(s) were created from a definition other than the stored template; a repin leaves them reading conflict",
			defect.KeyType, defect.ConflictAfterRepin, defect.Keys)
	}
	if defect.KeysFromStoredTemplate > 0 {
		logInfof("%s: %d of its %d key(s) were created from the stored template",
			defect.KeyType, defect.KeysFromStoredTemplate, defect.Keys)
	}
}

const otherDamageAdvice = "a repair would not let the signer unlock: repair that damage first and run the repair again, or rebuild the store from a backup (apstore rebuild)"

// adviseRefusal says what clears the damage that refused a repair.
func adviseRefusal(err error) {
	var member *storevalidate.DeletedArchiveMemberError
	switch {
	case errors.As(err, &member):
		logWarnf("unlock never opens the deleted archive, but every generation commit verifies it: start apsigner, remove the member with `apadmin archive prune --confirm %s`, stop apsigner, and repair again", member.Path)
	case errors.Is(err, templaterepair.ErrOtherDamage):
		logWarnf("%s", otherDamageAdvice)
	}
}

func defectLabel(defect templaterepair.Defect) string {
	if defect.TemplateType == "" {
		return string(defect.Kind)
	}
	return fmt.Sprintf("%s (%s)", defect.Kind, defect.TemplateType)
}
