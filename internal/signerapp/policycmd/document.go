// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policycmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/policyreview"
)

// ErrPolicyInvalid reports that check found errors; they have been printed.
var ErrPolicyInvalid = errors.New("policy is invalid")

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
		view, err := getPolicy(ctx, backend)
		if err != nil {
			return err
		}
		if view.NodeRole == "cosigner" && command.Key == "" {
			return fmt.Errorf("a cosigner node has one policy per key; choose one with --key")
		}
		doc, err := backend.Document(ctx, command.Key)
		if err != nil {
			return err
		}
		if !doc.Success {
			return resultError(doc.Code, doc.Error)
		}
		_, err = io.WriteString(streams.Stdout, doc.Document)
		return err
	case VerbCheck:
		view, err := getPolicy(ctx, backend)
		if err != nil {
			return err
		}
		docs, names, err := policyreview.ReadDocuments(command.Args, view.NodeRole, streams.Stdin)
		if err != nil {
			return err
		}
		return checkDocuments(ctx, backend, streams, adminproto.CheckPolicyRequest{Documents: docs}, names)
	case VerbDiff:
		view, err := getPolicy(ctx, backend)
		if err != nil {
			return err
		}
		docs, names, err := policyreview.ReadDocuments(command.Args, view.NodeRole, streams.Stdin)
		if err != nil {
			return err
		}
		diffs, err := diffChange(ctx, backend, view.NodeRole, docs, nil, names)
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
			if req.Documents, names, err = policyreview.ReadDocuments(command.Args, view.NodeRole, streams.Stdin); err != nil {
				return err
			}
		} else {
			if view.NodeRole != "cosigner" {
				return fmt.Errorf("policy remove applies only to cosigner nodes")
			}
			req.Remove = command.Args
		}
		if err := checkDocuments(ctx, backend, streams, adminproto.CheckPolicyRequest{Documents: req.Documents, Remove: req.Remove}, names); err != nil {
			return err
		}
		diffs, err := diffChange(ctx, backend, view.NodeRole, req.Documents, req.Remove, names)
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
	if view.NodeRole == "signer" {
		_, _ = fmt.Fprintln(w, "signer policy")
		for _, doc := range view.Documents {
			_, _ = fmt.Fprintf(w, "  policy.json  %s\n", documentSummary(doc))
		}
	} else {
		byKey := make(map[string]adminproto.PolicyDocumentInfo, len(view.Documents))
		for _, doc := range view.Documents {
			byKey[doc.Key] = doc
		}
		_, _ = fmt.Fprintf(w, "cosigner policies (%d keys)\n", len(view.Keys))
		for _, st := range view.Keys {
			switch st.Status {
			case adminproto.PolicyKeyNoPolicy:
				_, _ = fmt.Fprintf(w, "  %s  no policy     rejects every request\n", st.Key)
			case adminproto.PolicyKeyNotHeld:
				_, _ = fmt.Fprintf(w, "  %s  key not held  %s\n", st.Key, documentSummary(byKey[st.Key]))
			default:
				_, _ = fmt.Fprintf(w, "  %s  active        %s\n", st.Key, documentSummary(byKey[st.Key]))
			}
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
// node's active document for the same key.
func diffChange(ctx context.Context, backend Backend, role string, docs []adminproto.PolicyDocument, remove []string, names map[string]string) ([]policyreview.DocumentDiff, error) {
	var out []policyreview.DocumentDiff
	for _, doc := range docs {
		current, err := backend.Document(ctx, doc.Key)
		if err != nil {
			return nil, err
		}
		if !current.Success && current.Code != "policy_document_not_found" {
			return nil, resultError(current.Code, current.Error)
		}
		label := names[doc.Key]
		changes, identical, err := policyreview.DiffDocument(role, doc.Key, current.Success, current.Document, doc.Document)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", label, err)
		}
		out = append(out, policyreview.DocumentDiff{Label: label, Changes: changes, Identical: identical})
	}
	for _, key := range remove {
		current, err := backend.Document(ctx, key)
		if err != nil {
			return nil, err
		}
		if !current.Success {
			return nil, resultError(current.Code, current.Error)
		}
		previous, err := policy.DecodeCosignerPolicyV1([]byte(current.Document), key)
		if err != nil {
			return nil, fmt.Errorf("active policy for %s: %w", key, err)
		}
		out = append(out, policyreview.DocumentDiff{Label: key, Changes: policy.DiffCosignerPolicyV1(previous, nil)})
	}
	return out, nil
}
