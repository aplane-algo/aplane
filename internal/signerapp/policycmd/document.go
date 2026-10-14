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
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/policyreview"
)

// ErrPolicyInvalid reports that check found errors; they have been printed.
var ErrPolicyInvalid = errors.New("policy is invalid")

// WriteEmbeddedTemplate writes the shipped default for the role named by
// --embedded, as the starting document for --key (or as the default itself).
// It needs no node and no passphrase, and is the only template form that
// does not print a node's own default.
func WriteEmbeddedTemplate(command Command, streams Streams) error {
	if err := command.Validate(); err != nil {
		return err
	}
	if command.Verb != VerbTemplate || command.Embedded == "" {
		return fmt.Errorf("policy template --embedded signer|cosigner is required without a node")
	}
	role, err := noderole.ParseRole(command.Embedded)
	if err != nil {
		return err
	}
	text, err := policyreview.EmbeddedTemplate(role, command.documentKey())
	if err != nil {
		return err
	}
	_, err = io.WriteString(streams.normalized().Stdout, text)
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
		doc, err := backend.Document(ctx, command.documentKey())
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
		def, err := backend.Document(ctx, policy.DefaultKey)
		if err != nil {
			return err
		}
		if !def.Success {
			return resultError(def.Code, def.Error)
		}
		text, err := policyreview.Template(role, command.documentKey(), []byte(def.Document))
		if err != nil {
			return err
		}
		_, err = io.WriteString(streams.Stdout, text)
		return err
	case VerbCheck:
		docs, names, err := policyreview.ReadDocuments(command.Args, streams.Stdin)
		if err != nil {
			return err
		}
		return checkDocuments(ctx, backend, streams, adminproto.CheckPolicyRequest{Documents: docs}, names)
	case VerbDiff:
		view, err := getPolicy(ctx, backend)
		if err != nil {
			return err
		}
		docs, names, err := policyreview.ReadDocuments(command.Args, streams.Stdin)
		if err != nil {
			return err
		}
		diffs, err := diffChange(ctx, backend, view, docs, nil, names)
		if err != nil {
			return err
		}
		policyreview.PrintDiffs(streams.Stdout, diffs)
		return nil
	case VerbApply, VerbRemove:
		view, err := getPolicy(ctx, backend)
		if err != nil {
			return err
		}
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
		diffs, err := diffChange(ctx, backend, view, req.Documents, req.Remove, names)
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
		req.ExpectedPolicySetSHA256 = view.PolicySetSHA256
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
func diffChange(ctx context.Context, backend Backend, view adminproto.PolicyView, docs []adminproto.PolicyDocument, remove []string, names map[string]string) ([]policyreview.DocumentDiff, error) {
	role, err := noderole.ParseRole(view.NodeRole)
	if err != nil {
		return nil, err
	}
	own := map[string]bool{}
	for _, doc := range view.Documents {
		own[doc.Key] = true
	}
	fetch := func(key string) (string, error) {
		current, err := backend.Document(ctx, key)
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
			label += governedKeysNote(view, remove)
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

// governedKeysNote names the held keys a changed default reaches: those on
// the default now, plus those losing their own document in the same change.
func governedKeysNote(view adminproto.PolicyView, remove []string) string {
	var governed []string
	for _, st := range view.Keys {
		if st.Status == adminproto.PolicyKeyDefault {
			governed = append(governed, st.Key)
		}
	}
	governed = append(governed, remove...)
	if len(governed) == 0 {
		return " (governs no held key; every held key has a policy of its own)"
	}
	return fmt.Sprintf(" (governs %d held key(s): %s)", len(governed), strings.Join(governed, ", "))
}
