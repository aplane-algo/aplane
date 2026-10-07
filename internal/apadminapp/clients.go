// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apadminapp

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/protocol"
)

const clientsUsage = "usage: apadmin clients <list|approve|reject|import|revoke>"

// maxClientPublicKeyBytes bounds a public-key file before it is read.
const maxClientPublicKeyBytes = 16 * 1024

// clientsCommandAuth validates the clients subcommand and reports the session
// it needs. Listing is read-only; enrollment changes take an unlocked
// session like other registry mutations.
func clientsCommandAuth(args []string) (AuthMode, error) {
	if len(args) == 0 {
		return AuthUnlock, fmt.Errorf("%s", clientsUsage)
	}
	switch args[0] {
	case "list":
		if len(args) != 1 {
			return AuthReadOnly, fmt.Errorf("usage: apadmin clients list")
		}
		return AuthReadOnly, nil
	case "approve":
		if _, _, err := parseClientsFingerprintArgs("approve", args[1:], true); err != nil {
			return AuthUnlock, err
		}
		return AuthUnlock, nil
	case "reject", "revoke":
		if _, _, err := parseClientsFingerprintArgs(args[0], args[1:], false); err != nil {
			return AuthUnlock, err
		}
		return AuthUnlock, nil
	case "import":
		if _, _, err := parseClientsImportArgs(args[1:]); err != nil {
			return AuthUnlock, err
		}
		return AuthUnlock, nil
	}
	return AuthUnlock, fmt.Errorf("%s", clientsUsage)
}

func parseClientsFingerprintArgs(verb string, args []string, allowLabel bool) (fingerprint, label string, err error) {
	usage := fmt.Sprintf("usage: apadmin clients %s <fingerprint>", verb)
	if allowLabel {
		usage += " [--label <text>]"
	}
	positional, label, labelSet, err := splitClientsLabelFlag(args)
	if err != nil || len(positional) != 1 || (!allowLabel && labelSet) {
		return "", "", fmt.Errorf("%s", usage)
	}
	fingerprint = strings.TrimSpace(positional[0])
	if !strings.HasPrefix(fingerprint, "SHA256:") {
		return "", "", fmt.Errorf("%s: fingerprint must be the SHA256: form shown by apshell", usage)
	}
	return fingerprint, strings.TrimSpace(label), nil
}

func parseClientsImportArgs(args []string) (path, label string, err error) {
	const usage = "usage: apadmin clients import <public-key-file|-> [--label <text>]"
	positional, label, _, err := splitClientsLabelFlag(args)
	if err != nil || len(positional) != 1 {
		return "", "", fmt.Errorf("%s", usage)
	}
	return positional[0], strings.TrimSpace(label), nil
}

// splitClientsLabelFlag separates the one optional --label flag from the
// positional arguments of a clients verb. The flag is accepted before or
// after the positional argument, as the documented forms show it, which
// the standard flag package does not allow since it stops at the first
// positional. "--label <text>", "--label=<text>", and the single-dash
// spellings are all accepted; "--" ends flag parsing. Any other flag is an
// error, as is a repeated --label or one without a value.
func splitClientsLabelFlag(args []string) (positional []string, label string, labelSet bool, err error) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			positional = append(positional, arg)
			continue
		}
		name, value, hasValue := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		if name != "label" {
			return nil, "", false, fmt.Errorf("unknown flag %q", arg)
		}
		if labelSet {
			return nil, "", false, errors.New("--label given more than once")
		}
		if !hasValue {
			if i+1 >= len(args) {
				return nil, "", false, errors.New("--label needs a value")
			}
			i++
			value = args[i]
		}
		label, labelSet = value, true
	}
	return positional, label, labelSet, nil
}

func (c Catalog) runClients(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", clientsUsage)
	}
	switch args[0] {
	case "list":
		return c.listClients()
	case "approve":
		fingerprint, label, err := parseClientsFingerprintArgs("approve", args[1:], true)
		if err != nil {
			return err
		}
		return c.approveClient(fingerprint, label)
	case "reject":
		fingerprint, _, err := parseClientsFingerprintArgs("reject", args[1:], false)
		if err != nil {
			return err
		}
		return c.rejectClient(fingerprint)
	case "revoke":
		fingerprint, _, err := parseClientsFingerprintArgs("revoke", args[1:], false)
		if err != nil {
			return err
		}
		return c.revokeClient(fingerprint)
	case "import":
		path, label, err := parseClientsImportArgs(args[1:])
		if err != nil {
			return err
		}
		return c.importClient(path, label)
	default:
		return fmt.Errorf("%s", clientsUsage)
	}
}

// listClients prints the waiting enrollment requests and the enrolled keys.
func (c Catalog) listClients() error {
	var pending protocol.PendingEnrollmentsListMessage
	if err := c.Client.Request(protocol.ListPendingEnrollmentsMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeListPendingEnrollments, ID: c.requestID("clients-pending")},
	}, &pending); err != nil {
		return err
	}
	var enrolled protocol.EnrolledKeysListMessage
	if err := c.Client.Request(protocol.ListEnrolledKeysMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeListEnrolledKeys, ID: c.requestID("clients-list")},
	}, &enrolled); err != nil {
		return err
	}
	out := c.Streams.Stdout
	if len(pending.Requests) == 0 {
		c.info("no enrollment requests waiting")
	} else {
		c.info("%d enrollment request(s) waiting for approval", len(pending.Requests))
		for _, req := range pending.Requests {
			line := fmt.Sprintf("  pending   %s  %s", req.Fingerprint, req.KeyType)
			if req.Label != "" {
				line += "  " + req.Label
			}
			if req.RemoteAddr != "" {
				line += "  from " + req.RemoteAddr
			}
			line += "  " + time.Unix(req.RequestedAt, 0).UTC().Format(time.RFC3339)
			_, _ = fmt.Fprintln(out, line)
		}
	}
	if len(enrolled.Keys) == 0 {
		c.info("no enrolled client keys")
		return nil
	}
	c.info("%d enrolled client key(s)", len(enrolled.Keys))
	for _, key := range enrolled.Keys {
		line := fmt.Sprintf("  enrolled  %s  %s", key.Fingerprint, key.KeyType)
		if key.Label != "" {
			line += "  " + key.Label
		}
		if key.Connected {
			line += "  (connected)"
		}
		_, _ = fmt.Fprintln(out, line)
	}
	return nil
}

func (c Catalog) approveClient(fingerprint, label string) error {
	var result protocol.ApproveEnrollmentResultMessage
	if err := c.Client.Request(protocol.ApproveEnrollmentMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeApproveEnrollment, ID: c.requestID("clients-approve")},
		Fingerprint: fingerprint, Label: label,
	}, &result); err != nil {
		return err
	}
	if !result.Success {
		return resultError("enrollment approval failed", result.Code, result.Error)
	}
	if result.Label != "" {
		c.info("client key %s enrolled (label %q)", result.Fingerprint, result.Label)
	} else {
		c.info("client key %s enrolled", result.Fingerprint)
	}
	return nil
}

func (c Catalog) rejectClient(fingerprint string) error {
	var result protocol.RejectEnrollmentResultMessage
	if err := c.Client.Request(protocol.RejectEnrollmentMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeRejectEnrollment, ID: c.requestID("clients-reject")},
		Fingerprint: fingerprint,
	}, &result); err != nil {
		return err
	}
	if !result.Success {
		return resultError("enrollment rejection failed", result.Code, result.Error)
	}
	c.info("enrollment request for %s rejected", fingerprint)
	return nil
}

func (c Catalog) revokeClient(fingerprint string) error {
	var result protocol.RevokeEnrolledKeyResultMessage
	if err := c.Client.Request(protocol.RevokeEnrolledKeyMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeRevokeEnrolledKey, ID: c.requestID("clients-revoke")},
		Fingerprint: fingerprint,
	}, &result); err != nil {
		return err
	}
	if !result.Success {
		return resultError("client key revocation failed", result.Code, result.Error)
	}
	c.info("client key %s revoked; closed %d connection(s)", fingerprint, result.ClosedConnections)
	return nil
}

// importClient pre-enrolls a public key from a file, or from stdin when path
// is "-". The file holds one OpenSSH public-key line; its comment is the
// label unless --label is given.
func (c Catalog) importClient(path, label string) error {
	data, err := readClientPublicKey(path, c.Streams.Stdin)
	if err != nil {
		return err
	}
	var result protocol.ImportClientKeyResultMessage
	if err := c.Client.Request(protocol.ImportClientKeyMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeImportClientKey, ID: c.requestID("clients-import")},
		PublicKey:   data, Label: label,
	}, &result); err != nil {
		return err
	}
	if !result.Success {
		return resultError("client key import failed", result.Code, result.Error)
	}
	switch {
	case !result.Added:
		c.info("client key %s was already enrolled", result.Fingerprint)
	case result.Label != "":
		c.info("client key %s enrolled (label %q)", result.Fingerprint, result.Label)
	default:
		c.info("client key %s enrolled", result.Fingerprint)
	}
	return nil
}

// ReadClientPublicKeyFile reads one OpenSSH public-key line from a file on
// this machine, for pre-enrollment.
func ReadClientPublicKeyFile(path string) (string, error) {
	return readClientPublicKey(path, nil)
}

func readClientPublicKey(path string, stdin io.Reader) (string, error) {
	var data []byte
	if path == "-" {
		if stdin == nil {
			return "", fmt.Errorf("cannot read the public key from stdin: stdin is unavailable")
		}
		limited, err := io.ReadAll(io.LimitReader(stdin, maxClientPublicKeyBytes+1))
		if err != nil {
			return "", fmt.Errorf("failed to read the public key from stdin: %w", err)
		}
		if len(limited) > maxClientPublicKeyBytes {
			return "", fmt.Errorf("public key from stdin exceeds %d bytes", maxClientPublicKeyBytes)
		}
		data = limited
	} else {
		var err error
		data, _, err = fsutil.ReadRegularFileLimited(path, maxClientPublicKeyBytes)
		if err != nil {
			return "", fmt.Errorf("failed to read public key file: %w", err)
		}
	}
	text := strings.TrimSpace(string(data))
	if text == "" {
		return "", fmt.Errorf("public key is empty")
	}
	if strings.ContainsAny(text, "\r\n") {
		return "", fmt.Errorf("public key must be a single OpenSSH public-key line")
	}
	return text, nil
}
