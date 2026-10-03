// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policycmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
	"unicode/utf8"

	"github.com/aplane-algo/aplane/internal/adminproto"
)

// maxPolicyFileBytes bounds what a policy file read accepts; the node
// rejects larger documents.
const maxPolicyFileBytes = 1 << 20

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
		docs, names, err := readDocuments(command.Args, view.NodeRole, streams.Stdin)
		if err != nil {
			return err
		}
		return checkDocuments(ctx, backend, streams, adminproto.CheckPolicyRequest{Documents: docs}, names)
	case VerbApply, VerbRemove:
		view, err := getPolicy(ctx, backend)
		if err != nil {
			return err
		}
		var req adminproto.ApplyPolicyRequest
		names := map[string]string{}
		if command.Verb == VerbApply {
			if req.Documents, names, err = readDocuments(command.Args, view.NodeRole, streams.Stdin); err != nil {
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
		req.ExpectedPolicySetSHA256 = view.PolicySetSHA256
		result, err := backend.Apply(ctx, req)
		if err != nil {
			return err
		}
		if !result.Success {
			printProblems(streams.Stderr, "error", result.Errors, names)
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
	printProblems(streams.Stderr, "error", result.Errors, names)
	printProblems(streams.Stderr, "warning", result.Warnings, names)
	if !result.Valid {
		return ErrPolicyInvalid
	}
	if len(req.Documents) > 0 {
		_, _ = fmt.Fprintln(streams.Stdout, "policy OK")
	}
	return nil
}

// readDocuments reads policy files for the node's role. A signer node takes
// one file; each cosigner file names its key in its "key" field. names maps a
// document's key to the file it came from, for messages.
func readDocuments(files []string, role string, stdin io.Reader) ([]adminproto.PolicyDocument, map[string]string, error) {
	if role == "signer" && len(files) != 1 {
		return nil, nil, fmt.Errorf("a signer node takes exactly one policy file")
	}
	docs := make([]adminproto.PolicyDocument, 0, len(files))
	names := make(map[string]string, len(files))
	for _, file := range files {
		data, err := readPolicyFile(file, stdin)
		if err != nil {
			return nil, nil, err
		}
		doc := adminproto.PolicyDocument{Document: string(data)}
		if role == "cosigner" {
			var head struct {
				Key string `json:"key"`
			}
			if err := json.Unmarshal(data, &head); err != nil || head.Key == "" {
				return nil, nil, fmt.Errorf("%s: a cosigner policy file must be a JSON object with a \"key\" field", file)
			}
			doc.Key = head.Key
		}
		if other, dup := names[doc.Key]; dup {
			return nil, nil, fmt.Errorf("%s and %s are both policies for %s", other, file, doc.Key)
		}
		names[doc.Key] = file
		docs = append(docs, doc)
	}
	return docs, names, nil
}

func readPolicyFile(file string, stdin io.Reader) ([]byte, error) {
	r := stdin
	if file != "-" {
		f, err := os.Open(file)
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		r = f
	}
	data, err := io.ReadAll(io.LimitReader(r, maxPolicyFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", file, err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("%s is empty", file)
	}
	// JSON encoding would replace invalid UTF-8, so the node would not
	// receive the file's exact bytes.
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("%s is not valid UTF-8", file)
	}
	return data, nil
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

func printProblems(w io.Writer, label string, problems []adminproto.PolicyProblem, names map[string]string) {
	for _, problem := range problems {
		where := names[problem.Key]
		if where == "" {
			where = problem.Key
		}
		if problem.Pointer != "" {
			where += " " + problem.Pointer
		}
		if where != "" {
			where += ": "
		}
		_, _ = fmt.Fprintf(w, "%s: %s%s\n", label, where, problem.Message)
	}
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
