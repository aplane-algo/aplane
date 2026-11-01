// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policycmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/apadminapp"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policyexport"
	"github.com/aplane-algo/aplane/internal/signerapp/policyreview"
	"github.com/aplane-algo/aplane/internal/signerapp/policytext"
)

// ErrPolicyInvalid reports that check found errors; they have been printed.
var ErrPolicyInvalid = errors.New("policy is invalid")

// WriteOfflineTemplate writes a template apadmin carries itself: the
// shipped default for the role named by --embedded, or the cosigner preset
// named by --preset, as the starting document for --key (or as the default
// itself); or, for --list-presets, the list of cosigner presets. It needs no
// node and no passphrase. Every other template form prints a node's own
// default.
func WriteOfflineTemplate(command Command, streams Streams) error {
	if err := command.Validate(); err != nil {
		return err
	}
	if !command.NeedsNoNode() {
		return fmt.Errorf("policy template --embedded signer|cosigner, --preset NAME, or --list-presets is required without a node")
	}
	stdout := streams.normalized().Stdout
	var text string
	switch {
	case command.ListPresets:
		var b strings.Builder
		for _, preset := range policytext.Presets(noderole.RoleCosigner) {
			fmt.Fprintf(&b, "%-20s %s\n", preset.Name, preset.Summary)
		}
		text = b.String()
	case command.Preset != "":
		var err error
		if text, err = policytext.PresetTemplate(noderole.RoleCosigner, command.Preset, command.documentKey()); err != nil {
			return err
		}
	default:
		role, err := noderole.ParseRole(command.Embedded)
		if err != nil {
			return err
		}
		if text, err = policytext.EmbeddedTemplate(role, command.documentKey()); err != nil {
			return err
		}
	}
	_, err := io.WriteString(stdout, text)
	return err
}

// run executes one verb against a backend.
func run(ctx context.Context, command Command, streams Streams, backend Backend) error {
	switch command.Verb {
	case VerbStatus:
		view, err := getPolicy(ctx, backend)
		if err != nil {
			return err
		}
		printStatus(streams.Stdout, view)
		return nil
	case VerbExport:
		if command.ExportDir != "" {
			return exportAll(ctx, backend, streams, command.ExportDir)
		}
		doc, err := backend.Document(ctx, command.documentKey(), "")
		if err != nil {
			return err
		}
		if !doc.Success {
			return resultError(doc.Code, doc.Error)
		}
		_, err = io.WriteString(streams.Stdout, doc.Document)
		return err
	case VerbTemplate:
		view, err := getPolicy(ctx, backend)
		if err != nil {
			return err
		}
		role, err := noderole.ParseRole(view.NodeRole)
		if err != nil {
			return err
		}
		def, err := backend.Document(ctx, policy.DefaultKey, "")
		if err != nil {
			return err
		}
		if !def.Success {
			return resultError(def.Code, def.Error)
		}
		text, err := policytext.Template(role, command.documentKey(), []byte(def.Document))
		if err != nil {
			return err
		}
		_, err = io.WriteString(streams.Stdout, text)
		return err
	case VerbCheck:
		selected, err := selectExport(command, streams)
		if err != nil {
			return err
		}
		if selected != nil {
			_, pctx, err := getReviewState(ctx, backend)
			if err != nil {
				return err
			}
			if err := compareExport(selected, pctx); err != nil {
				return err
			}
		}
		docs, names, err := policyreview.ReadDocuments(command.Args, streams.Stdin)
		if err != nil {
			return err
		}
		return checkDocuments(ctx, backend, streams, adminproto.CheckPolicyRequest{Documents: docs}, names)
	case VerbDiff:
		selected, err := selectExport(command, streams)
		if err != nil {
			return err
		}
		view, pctx, err := getReviewState(ctx, backend)
		if err != nil {
			return err
		}
		if err := compareExport(selected, pctx); err != nil {
			return err
		}
		snapshot := pctx.SnapshotSHA256
		docs, names, err := policyreview.ReadDocuments(command.Args, streams.Stdin)
		if err != nil {
			return err
		}
		diffs, err := diffChange(ctx, backend, view, snapshot, docs, nil, names)
		if err != nil {
			return err
		}
		policyreview.PrintDiffs(streams.Stdout, diffs)
		return nil
	case VerbApply, VerbRemove:
		var selected *policyexport.Selected
		if command.Verb == VerbApply {
			var err error
			if selected, err = selectExport(command, streams); err != nil {
				return err
			}
		}
		view, pctx, err := getReviewState(ctx, backend)
		if err != nil {
			return err
		}
		if err := compareExport(selected, pctx); err != nil {
			return err
		}
		snapshot := pctx.SnapshotSHA256
		var req adminproto.ApplyPolicyRequest
		names := map[string]string{}
		if command.Verb == VerbApply {
			if req.Documents, names, err = policyreview.ReadDocuments(command.Args, streams.Stdin); err != nil {
				return err
			}
		} else {
			req.Remove = command.Args
		}
		if err := checkDocuments(ctx, backend, streams, adminproto.CheckPolicyRequest{Documents: req.Documents, Remove: req.Remove}, names); err != nil {
			return err
		}
		diffs, err := diffChange(ctx, backend, view, snapshot, req.Documents, req.Remove, names)
		if err != nil {
			return err
		}
		if policyreview.Unchanged(diffs) {
			_, _ = fmt.Fprintln(streams.Stdout, "policy unchanged")
			return nil
		}
		policyreview.PrintDiffs(streams.Stdout, diffs)
		if !command.Yes {
			confirmed, err := ConfirmApply()
			if err != nil {
				return err
			}
			if !confirmed {
				return ErrApplyNotConfirmed
			}
		}
		// The commit is refused if anything the review saw moved: the
		// documents, the ASA set or the network mapping.
		req.ExpectedPolicySetSHA256 = view.PolicySetSHA256
		req.ExpectedSnapshotSHA256 = snapshot
		result, err := backend.Apply(ctx, req)
		if err != nil {
			return err
		}
		if !result.Success {
			policyreview.PrintProblems(streams.Stderr, "error", result.Errors, names)
			return resultError(result.Code, result.Error)
		}
		if result.Policy == nil || result.Policy.GenerationID == "" {
			_, _ = fmt.Fprintln(streams.Stdout, "policy unchanged")
			return nil
		}
		_, _ = fmt.Fprintf(streams.Stdout, "policy applied as generation %s\npolicy_set_sha256 %s\n",
			result.Policy.GenerationID, result.Policy.PolicySetSHA256)
		return nil
	default:
		return fmt.Errorf("unsupported policy command %q", command.Verb)
	}
}

// getReviewState reads the policy summary and the node's context, and
// returns the summary with the composite snapshot a review is made against.
// The two reads must describe one state; if the policy moved between them,
// the review is refused rather than mixing two states.
func getReviewState(ctx context.Context, backend Backend) (adminproto.PolicyView, adminproto.PolicyContextView, error) {
	view, err := getPolicy(ctx, backend)
	if err != nil {
		return view, adminproto.PolicyContextView{}, err
	}
	pctx, err := backend.Context(ctx)
	if err != nil {
		return view, pctx, err
	}
	if !pctx.Success {
		return view, pctx, resultError(pctx.Code, pctx.Error)
	}
	if pctx.PolicySetSHA256 != view.PolicySetSHA256 || pctx.SnapshotSHA256 == "" {
		return view, pctx, resultError("policy_snapshot_changed", "the node's policy changed while it was being read; run the command again")
	}
	return view, pctx, nil
}

// exportAll writes every document the node holds, and its context, into dir.
// Each document is fetched against the snapshot the summary and context were
// read at, so the node refuses a fetch once either moved; the writer checks
// every document against the summary before anything is written.
func exportAll(ctx context.Context, backend Backend, streams Streams, dir string) error {
	view, pctx, err := getReviewState(ctx, backend)
	if err != nil {
		return err
	}
	docs := make([]policyexport.Document, 0, len(view.Documents))
	for _, info := range view.Documents {
		doc, err := backend.Document(ctx, info.Key, pctx.SnapshotSHA256)
		if err != nil {
			return err
		}
		if !doc.Success {
			return resultError(doc.Code, doc.Error)
		}
		docs = append(docs, policyexport.Document{Key: info.Key, Document: doc.Document, SHA256: info.SHA256})
	}
	paths, err := apadminapp.WritePolicyExport(dir, docs, pctx, time.Now())
	if err != nil {
		if len(paths) > 0 {
			return fmt.Errorf("%w; the unfinished export is left in %s", err, dir)
		}
		return err
	}
	_, _ = fmt.Fprintf(streams.Stdout, "exported %d policy document(s) and the node context to %s\n", len(paths), dir)
	return nil
}

// selectExport finds the export context the files come from, unless the
// command compares none. Files not from an export have none; that is said,
// since their review then has no export baseline to compare.
func selectExport(command Command, streams Streams) (*policyexport.Selected, error) {
	if command.NoNodeContext {
		_, _ = fmt.Fprintln(streams.Stderr, "note: --no-node-context: the files are compared with the node as it is now, with no export baseline")
		return nil, nil
	}
	selected, err := policyexport.Discover(command.Args, command.NodeContext)
	if err != nil {
		return nil, err
	}
	if selected == nil {
		_, _ = fmt.Fprintln(streams.Stderr, "note: the files are not from an export; they are compared with the node as it is now, with no export baseline")
	}
	return selected, nil
}

// compareExport refuses files from an export the node has moved on from:
// its policy, or its context, is no longer what was exported. The edits must
// be carried over to a new export rather than applied over changes the
// export never saw.
func compareExport(selected *policyexport.Selected, pctx adminproto.PolicyContextView) error {
	if selected == nil {
		return nil
	}
	baseline := selected.Export.Baseline
	if baseline.SnapshotSHA256 == pctx.SnapshotSHA256 {
		return nil
	}
	var moved []string
	if baseline.PolicySetSHA256 != pctx.PolicySetSHA256 {
		moved = append(moved, "policy")
	}
	if selected.Export.Context.SHA256() != pctx.ContextSHA256 {
		moved = append(moved, "ASA set, network map or role")
	}
	if len(moved) == 0 {
		moved = append(moved, "policy context")
	}
	return resultError("policy_export_stale", fmt.Sprintf(
		"the export %s (taken %s) is stale: the node's %s changed since; export again and carry your edits over",
		selected.Path, selected.Export.ExportedAt.Format(time.RFC3339), strings.Join(moved, " and ")))
}

func getPolicy(ctx context.Context, backend Backend) (adminproto.PolicyView, error) {
	view, err := backend.Get(ctx)
	if err != nil {
		return view, err
	}
	if !view.Success {
		return view, resultError(view.Code, view.Error)
	}
	return view, nil
}

// checkDocuments runs check, prints its problems, and fails when the
// documents are invalid.
func checkDocuments(ctx context.Context, backend Backend, streams Streams, req adminproto.CheckPolicyRequest, names map[string]string) error {
	result, err := backend.Check(ctx, req)
	if err != nil {
		return err
	}
	if !result.Success {
		return resultError(result.Code, result.Error)
	}
	policyreview.PrintProblems(streams.Stderr, "error", result.Errors, names)
	policyreview.PrintProblems(streams.Stderr, "warning", result.Warnings, names)
	if !result.Valid {
		return ErrPolicyInvalid
	}
	if len(req.Documents) > 0 {
		_, _ = fmt.Fprintln(streams.Stdout, "policy OK")
	}
	return nil
}

func printStatus(w io.Writer, view adminproto.PolicyView) {
	byKey := make(map[string]adminproto.PolicyDocumentInfo, len(view.Documents))
	for _, doc := range view.Documents {
		byKey[doc.Key] = doc
	}
	_, _ = fmt.Fprintf(w, "%s policy\n", view.NodeRole)
	if def, ok := byKey[policy.DefaultKey]; ok {
		_, _ = fmt.Fprintf(w, "  default       %s\n", documentSummary(def))
	}
	_, _ = fmt.Fprintf(w, "keys (%d)\n", len(view.Keys))
	for _, st := range view.Keys {
		switch st.Status {
		case adminproto.PolicyKeyOwn:
			_, _ = fmt.Fprintf(w, "  %s  own policy    %s\n", st.Key, documentSummary(byKey[st.Key]))
		case adminproto.PolicyKeyNotHeld:
			_, _ = fmt.Fprintf(w, "  %s  key not held  %s\n", st.Key, documentSummary(byKey[st.Key]))
		default:
			_, _ = fmt.Fprintf(w, "  %s  default\n", st.Key)
		}
	}
	_, _ = fmt.Fprintf(w, "policy_set_sha256 %s\n", view.PolicySetSHA256)
}

func documentSummary(doc adminproto.PolicyDocumentInfo) string {
	summary := fmt.Sprintf("sha256 %s  %d bytes", doc.SHA256, doc.Size)
	if doc.SignedAtUnix > 0 {
		summary += "  applied " + time.Unix(doc.SignedAtUnix, 0).UTC().Format(time.RFC3339)
	}
	return summary
}

func resultError(code, msg string) error {
	if msg == "" {
		msg = "policy request failed"
	}
	if code == "" {
		return errors.New(msg)
	}
	return fmt.Errorf("%s (%s)", msg, code)
}

// diffChange compares each submitted document, and each removal, with the
// document that governs its key now. A key without a document of its own is
// compared with the node default; a removal is compared with the default in
// force after the change, which is the submitted one when the same change
// replaces it. A change to the default also lists the held keys it governs.
func diffChange(ctx context.Context, backend Backend, view adminproto.PolicyView, snapshot string, docs []adminproto.PolicyDocument, remove []string, names map[string]string) ([]policyreview.DocumentDiff, error) {
	role, err := noderole.ParseRole(view.NodeRole)
	if err != nil {
		return nil, err
	}
	own := map[string]bool{}
	for _, doc := range view.Documents {
		own[doc.Key] = true
	}
	fetch := func(key string) (string, error) {
		// Read against the reviewed snapshot: a document that moved since is
		// refused, so the diff shows the state the apply will be checked
		// against.
		current, err := backend.Document(ctx, key, snapshot)
		if err != nil {
			return "", err
		}
		if !current.Success {
			return "", resultError(current.Code, current.Error)
		}
		return current.Document, nil
	}
	activeDefault, err := fetch(policy.DefaultKey)
	if err != nil {
		return nil, err
	}
	nextDefault := activeDefault
	var out []policyreview.DocumentDiff
	for _, doc := range docs {
		label := names[doc.Key]
		if label == "" {
			label = doc.Key
		}
		current, ownCurrent := activeDefault, false
		if own[doc.Key] {
			if current, err = fetch(doc.Key); err != nil {
				return nil, err
			}
			ownCurrent = true
		}
		changes, identical, err := policyreview.DiffCandidate(role, doc.Key, current, doc.Document, ownCurrent)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", label, err)
		}
		if doc.Key == policy.DefaultKey {
			nextDefault = doc.Document
			label += governedKeysNote(view, docs, remove)
		}
		out = append(out, policyreview.DocumentDiff{Label: label, Changes: changes, Identical: identical})
	}
	for _, key := range remove {
		current, err := fetch(key)
		if err != nil {
			return nil, err
		}
		changes, err := policyreview.DiffRemoval(role, key, current, nextDefault)
		if err != nil {
			return nil, err
		}
		out = append(out, policyreview.DocumentDiff{Label: key, Changes: changes})
	}
	return out, nil
}

// governedKeysNote names the held keys a changed default reaches once the
// whole change is applied: those on the default now that are not gaining a
// document of their own in the same change, plus held keys losing theirs.
func governedKeysNote(view adminproto.PolicyView, docs []adminproto.PolicyDocument, remove []string) string {
	gaining := map[string]bool{}
	for _, doc := range docs {
		if doc.Key != policy.DefaultKey {
			gaining[doc.Key] = true
		}
	}
	removing := map[string]bool{}
	for _, key := range remove {
		removing[key] = true
	}
	var governed []string
	for _, st := range view.Keys {
		switch {
		case st.Status == adminproto.PolicyKeyDefault && !gaining[st.Key]:
			governed = append(governed, st.Key)
		case st.Status == adminproto.PolicyKeyOwn && removing[st.Key] && !gaining[st.Key]:
			governed = append(governed, st.Key)
		}
	}
	if len(governed) == 0 {
		return " (governs no held key; every held key has a policy of its own)"
	}
	return fmt.Sprintf(" (governs %d held key(s): %s)", len(governed), strings.Join(governed, ", "))
}
