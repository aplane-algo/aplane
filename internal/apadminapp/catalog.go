// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apadminapp

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/backup"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/endpointrefs"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/keytypefmt"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/witness"

	"gopkg.in/yaml.v3"
)

const (
	maxSentryPublicEnvelopeBytes = 64 * 1024
	inspectionRetryInterval      = 100 * time.Millisecond
)

// Requester is the correlated request seam used by live-admin workflows.
type Requester interface {
	Request(message, result any) error
	RequestWithTimeout(message, result any, timeout time.Duration) error
}

// Streams separates machine output from prompts and status.
type Streams struct {
	Stdout io.Writer
	Stderr io.Writer
}

func (s Streams) normalized() Streams {
	if s.Stdout == nil {
		s.Stdout = io.Discard
	}
	if s.Stderr == nil {
		s.Stderr = io.Discard
	}
	return s
}

// Catalog runs live catalog, handoff, and inspection commands.
type Catalog struct {
	Client  Requester
	Streams Streams
	Confirm func(prompt string) bool
	Now     func() time.Time
	Sleep   func(time.Duration)
}

func (c Catalog) normalized() Catalog {
	c.Streams = c.Streams.normalized()
	if c.Confirm == nil {
		c.Confirm = func(string) bool { return false }
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Sleep == nil {
		c.Sleep = time.Sleep
	}
	return c
}

// CatalogAuthMode returns the lock-state behavior required by a catalog
// command. It validates enough grammar to reject unknown verbs before a
// connection or passphrase prompt.
func CatalogAuthMode(command string, args []string) (AuthMode, error) {
	switch command {
	case "template":
		if len(args) == 0 {
			return AuthUnlock, fmt.Errorf("usage: apadmin template <list|show|import|remove>")
		}
		switch args[0] {
		case "list":
			if len(args) != 1 {
				return AuthUnlock, fmt.Errorf("usage: apadmin template list")
			}
			return AuthUnlock, nil
		case "show":
			if len(args) != 3 || args[2] != "--show-sensitive-template" {
				return AuthUnlock, fmt.Errorf("usage: apadmin template show <key-type> --show-sensitive-template")
			}
			return AuthUnlock, nil
		case "import", "remove":
			if len(args) != 2 {
				return AuthUnlock, fmt.Errorf("usage: apadmin template %s <file-or-key-type>", args[0])
			}
			return AuthUnlock, nil
		}
	case "keytype":
		if len(args) == 2 && (args[0] == "enable" || args[0] == "disable") {
			return AuthUnlock, nil
		}
	case "sentry":
		if len(args) == 0 {
			return AuthUnlock, fmt.Errorf("usage: apadmin sentry <export|import|list|show|remove>")
		}
		switch args[0] {
		case "export":
			if len(args) < 2 || len(args) > 3 {
				return AuthReadOnly, fmt.Errorf("usage: apadmin sentry export <sentry-key-id> [output-json]")
			}
			return AuthReadOnly, nil
		case "list":
			if len(args) != 1 {
				return AuthReadOnly, fmt.Errorf("usage: apadmin sentry list")
			}
			return AuthReadOnly, nil
		case "show":
			if len(args) != 2 {
				return AuthReadOnly, fmt.Errorf("usage: apadmin sentry show <name>")
			}
			return AuthReadOnly, nil
		case "import":
			if len(args) != 3 {
				return AuthUnlock, fmt.Errorf("usage: apadmin sentry import <export-json> <name>")
			}
			return AuthUnlock, nil
		case "remove":
			if len(args) != 2 {
				return AuthUnlock, fmt.Errorf("usage: apadmin sentry remove <name>")
			}
			return AuthUnlock, nil
		}
	case "endpoint":
		if len(args) > 0 && args[0] == "export" {
			fs := flag.NewFlagSet("apadmin endpoint export", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			_ = fs.String("host", "", "")
			_ = fs.String("url", "", "")
			_ = fs.Int("signer-port", 0, "")
			_ = fs.Int("local-port", 0, "")
			_ = fs.String("out", "", "")
			if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
				return AuthReadOnly, errors.New(endpointExportUsage)
			}
			return AuthReadOnly, nil
		}
	case "generations":
		if len(args) == 1 && args[0] == "list" {
			return AuthReadOnly, nil
		}
	}
	return AuthUnlock, fmt.Errorf("unknown or malformed apadmin command: %s", strings.TrimSpace(command+" "+strings.Join(args, " ")))
}

// Run executes one validated catalog command using an already authenticated
// client.
func (c Catalog) Run(command string, args []string) error {
	c = c.normalized()
	if c.Client == nil {
		return fmt.Errorf("admin requester is required")
	}
	switch command {
	case "template":
		return c.runTemplate(args)
	case "keytype":
		return c.runKeyType(args)
	case "sentry":
		return c.runSentry(args)
	case "endpoint":
		return c.runEndpoint(args)
	case "generations":
		return c.runGenerations(args)
	default:
		return fmt.Errorf("unknown apadmin command %q", command)
	}
}

func (c Catalog) runTemplate(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: apadmin template <list|show|import|remove>")
	}
	switch args[0] {
	case "list":
		if len(args) != 1 {
			return fmt.Errorf("usage: apadmin template list")
		}
		return c.listTemplates()
	case "show":
		if len(args) != 3 || args[2] != "--show-sensitive-template" {
			return fmt.Errorf("usage: apadmin template show <key-type> --show-sensitive-template")
		}
		return c.showTemplate(args[1])
	case "import":
		if len(args) != 2 {
			return fmt.Errorf("usage: apadmin template import <yaml-file>")
		}
		return c.importTemplate(args[1])
	case "remove":
		if len(args) != 2 {
			return fmt.Errorf("usage: apadmin template remove <key-type>")
		}
		return c.removeTemplate(args[1])
	default:
		return fmt.Errorf("usage: apadmin template <list|show|import|remove>")
	}
}

func (c Catalog) listTemplates() error {
	var result protocol.InstalledTemplatesMessage
	if err := c.Client.Request(protocol.ListInstalledTemplatesMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeListInstalledTemplates, ID: c.requestID("template-list")},
	}, &result); err != nil {
		return err
	}
	if result.Error != "" {
		return resultError("template list failed", result.Code, result.Error)
	}
	if len(result.Templates) == 0 {
		c.info("no installed templates found")
		return nil
	}
	c.info("found %d installed template(s)", len(result.Templates))
	for _, item := range result.Templates {
		status := "disabled"
		if item.Enabled {
			status = "enabled"
		}
		_, _ = fmt.Fprintf(c.Streams.Stdout, "  %s  (%s, %s, %s)\n", displayKeyType(item.KeyType), backup.FormatFileSize(item.Size), item.TemplateType, status)
	}
	return nil
}

func (c Catalog) showTemplate(keyType string) error {
	var result protocol.ShowInstalledTemplateResultMessage
	if err := c.Client.Request(protocol.ShowInstalledTemplateMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeShowInstalledTemplate, ID: c.requestID("template-show")},
		KeyType:     canonicalKeyType(keyType),
	}, &result); err != nil {
		return err
	}
	defer result.TemplateYAML.Zero()
	if !result.Success {
		return resultError("template show failed", result.Code, result.Error)
	}
	c.info("template: %s (%s)", displayKeyType(result.KeyType), result.TemplateType)
	_, err := fmt.Fprintln(c.Streams.Stdout, string(result.TemplateYAML))
	return err
}

func (c Catalog) importTemplate(path string) error {
	templateYAML, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read template YAML: %w", err)
	}
	defer crypto.ZeroBytes(templateYAML)
	var result protocol.ImportInstalledTemplateResultMessage
	if err := c.Client.Request(protocol.ImportInstalledTemplateMessage{
		BaseMessage:  protocol.BaseMessage{Type: protocol.MsgTypeImportInstalledTemplate, ID: c.requestID("template-import")},
		TemplateYAML: protocol.SensitiveBytes(templateYAML),
	}, &result); err != nil {
		return err
	}
	if !result.Success {
		return resultError("template import failed", result.Code, result.Error)
	}
	if result.AlreadyExists {
		c.info("%s template %s is already installed", result.TemplateType, displayKeyType(result.KeyType))
		return nil
	}
	if templateUsesDefaultOpcodeCeiling(templateYAML) {
		c.warn("template declares no max_opcode_cost; using the compiled v42 single-group-member opcode ceiling (%d) for each applicable authorization path", lsigresource.SingleTransactionOpcodeCeiling)
	}
	c.info("%s template %s imported", result.TemplateType, displayKeyType(result.KeyType))
	return nil
}

func (c Catalog) removeTemplate(keyType string) error {
	keyType = canonicalKeyType(keyType)
	if !c.Confirm(fmt.Sprintf("Remove installed template %s? [y/N]: ", displayKeyType(keyType))) {
		return fmt.Errorf("template removal cancelled")
	}
	var result protocol.RemoveInstalledTemplateResultMessage
	if err := c.Client.Request(protocol.RemoveInstalledTemplateMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeRemoveInstalledTemplate, ID: c.requestID("template-remove")},
		KeyType:     keyType,
	}, &result); err != nil {
		return err
	}
	if !result.Success {
		return resultError("template remove failed", result.Code, result.Error)
	}
	if result.Removed {
		c.info("template %s removed", displayKeyType(result.KeyType))
	} else {
		c.info("template %s was already absent", displayKeyType(result.KeyType))
	}
	return nil
}

func (c Catalog) runKeyType(args []string) error {
	if len(args) != 2 || (args[0] != "enable" && args[0] != "disable") {
		return fmt.Errorf("usage: apadmin keytype <enable|disable> <key-type>")
	}
	keyType := canonicalKeyType(args[1])
	if args[0] == "enable" {
		var result protocol.ActivateKeyTypeResultMessage
		if err := c.Client.Request(protocol.ActivateKeyTypeMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeActivateKeyType, ID: c.requestID("keytype-enable")},
			KeyType:     keyType,
		}, &result); err != nil {
			return err
		}
		if !result.Success {
			return resultError("key type enable failed", result.Code, result.Error)
		}
		if result.AlreadyExists {
			c.info("key type %s was already enabled", displayKeyType(result.KeyType))
		} else {
			c.info("key type %s enabled", displayKeyType(result.KeyType))
		}
		return nil
	}
	if !c.Confirm(fmt.Sprintf("Disable key type %s? [y/N]: ", displayKeyType(keyType))) {
		return fmt.Errorf("key type disable cancelled")
	}
	var result protocol.DeactivateKeyTypeResultMessage
	if err := c.Client.Request(protocol.DeactivateKeyTypeMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeDeactivateKeyType, ID: c.requestID("keytype-disable")},
		KeyType:     keyType,
	}, &result); err != nil {
		return err
	}
	if !result.Success {
		return resultError("key type disable failed", result.Code, result.Error)
	}
	if result.Removed {
		c.info("key type %s disabled", displayKeyType(result.KeyType))
	} else {
		c.info("key type %s was already disabled", displayKeyType(result.KeyType))
	}
	return nil
}

func (c Catalog) runSentry(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: apadmin sentry <export|import|list|show|remove>")
	}
	switch args[0] {
	case "export":
		if len(args) < 2 || len(args) > 3 {
			return fmt.Errorf("usage: apadmin sentry export <sentry-key-id> [output-json]")
		}
		return c.exportSentry(args[1:])
	case "import":
		if len(args) != 3 {
			return fmt.Errorf("usage: apadmin sentry import <export-json> <name>")
		}
		return c.importSentry(args[1], args[2])
	case "list":
		if len(args) != 1 {
			return fmt.Errorf("usage: apadmin sentry list")
		}
		return c.listSentries()
	case "show":
		if len(args) != 2 {
			return fmt.Errorf("usage: apadmin sentry show <name>")
		}
		return c.showSentry(args[1])
	case "remove":
		if len(args) != 2 {
			return fmt.Errorf("usage: apadmin sentry remove <name>")
		}
		return c.removeSentry(args[1])
	default:
		return fmt.Errorf("usage: apadmin sentry <export|import|list|show|remove>")
	}
}

func (c Catalog) exportSentry(args []string) error {
	keyID, err := witness.NormalizeID(args[0])
	if err != nil {
		return fmt.Errorf("invalid Witness Key ID: %w", err)
	}
	result, err := requestInspectionWithRetry(c, func() any {
		return protocol.ExportSentryPublicMessage{
			BaseMessage:  protocol.BaseMessage{Type: protocol.MsgTypeExportSentryPublic, ID: c.requestID("sentry-export")},
			WitnessKeyID: keyID,
		}
	}, func(result *protocol.ExportSentryPublicResultMessage) string { return result.Code })
	if err != nil {
		return err
	}
	if !result.Success {
		return resultError("sentry export failed", result.Code, result.Error)
	}
	data := []byte(result.EnvelopeJSON)
	if len(args) == 1 {
		_, err := c.Streams.Stdout.Write(data)
		return err
	}
	if args[1] == "" {
		return fmt.Errorf("output path is required")
	}
	if err := fsutil.WriteFileDurableWithProfile(args[1], data, fsutil.PrivateStoreFileProfile); err != nil {
		return fmt.Errorf("failed to write public key envelope: %w", err)
	}
	c.info("sentry public key envelope written: %s", args[1])
	return nil
}

func (c Catalog) importSentry(path, name string) error {
	data, _, err := fsutil.ReadRegularFileLimited(path, maxSentryPublicEnvelopeBytes)
	if err != nil {
		return fmt.Errorf("failed to read sentry public key export: %w", err)
	}
	var result protocol.ImportSentryReferenceResultMessage
	if err := c.Client.Request(protocol.ImportSentryReferenceMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeImportSentryReference, ID: c.requestID("sentry-import")},
		Name:        name, EnvelopeJSON: string(data),
	}, &result); err != nil {
		return err
	}
	if !result.Success {
		return resultError("sentry import failed", result.Code, result.Error)
	}
	c.info("sentry reference %s imported for %s", result.Reference.Name, result.Reference.KeyType)
	return nil
}

func (c Catalog) listSentries() error {
	result, err := requestInspectionWithRetry(c, func() any {
		return protocol.ListSentryReferencesMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeListSentryReferences, ID: c.requestID("sentry-list")},
		}
	}, func(result *protocol.SentryReferencesListMessage) string { return result.Code })
	if err != nil {
		return err
	}
	if result.Error != "" {
		return resultError("sentry list failed", result.Code, result.Error)
	}
	if len(result.References) == 0 {
		c.info("no sentry references found")
		return nil
	}
	c.info("found %d sentry reference(s)", len(result.References))
	for _, record := range result.References {
		label := "unknown"
		if record.Name != "" {
			label = record.Name
		}
		_, _ = fmt.Fprintf(c.Streams.Stdout, "  %s  (%s, name: %s)\n", record.ComponentKey, record.KeyType, label)
	}
	return nil
}

func (c Catalog) showSentry(name string) error {
	result, err := requestInspectionWithRetry(c, func() any {
		return protocol.GetSentryReferenceMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeGetSentryReference, ID: c.requestID("sentry-show")},
			Name:        name,
		}
	}, func(result *protocol.SentryReferenceMessage) string { return result.Code })
	if err != nil {
		return err
	}
	if !result.Success {
		return resultError("sentry show failed", result.Code, result.Error)
	}
	data, err := json.MarshalIndent(result.Reference, "", "  ")
	if err != nil {
		return fmt.Errorf("encode sentry reference: %w", err)
	}
	_, err = c.Streams.Stdout.Write(append(data, '\n'))
	return err
}

func (c Catalog) removeSentry(name string) error {
	var result protocol.RemoveSentryReferenceResultMessage
	if err := c.Client.Request(protocol.RemoveSentryReferenceMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeRemoveSentryReference, ID: c.requestID("sentry-remove")},
		Name:        name,
	}, &result); err != nil {
		return err
	}
	if !result.Success {
		return resultError("sentry remove failed", result.Code, result.Error)
	}
	if result.Removed {
		c.info("sentry reference %s removed", name)
	} else {
		c.info("sentry reference %s was already absent", name)
	}
	return nil
}

type endpointExportSettings struct {
	AdvertiseURL string
	SSHPort      int
	SignerPort   int
}

const endpointExportUsage = "usage: apadmin endpoint export [--host <host> | --url <url>] [--signer-port <port>] [--local-port <port>] [--out endpoint.json]"

func (c Catalog) runEndpoint(args []string) error {
	if len(args) == 0 || args[0] != "export" {
		return fmt.Errorf("usage: apadmin endpoint <export>")
	}
	fs := flag.NewFlagSet("apadmin endpoint export", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	host := fs.String("host", "", "client-reachable SSH host or IP")
	endpointURL := fs.String("url", "", "endpoint URL")
	signerPort := fs.Int("signer-port", 0, "remote apsigner REST port")
	localPort := fs.Int("local-port", 0, "local tunnel port")
	outPath := fs.String("out", "", "output JSON path")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
		return errors.New(endpointExportUsage)
	}
	settings, err := c.loadEndpointSettings()
	if err != nil {
		return err
	}
	urlValue, err := endpointExportURL(*host, *endpointURL, settings.AdvertiseURL, endpointExportSSHPort(settings))
	if err != nil {
		return err
	}
	signerPortValue := *signerPort
	if signerPortValue == 0 && endpointExportUsesSSH(urlValue) {
		signerPortValue = endpointExportSignerPort(settings)
	}
	envelope, err := endpointrefs.Normalize(endpointrefs.Envelope{
		Schema: endpointrefs.Schema, URL: urlValue, SignerPort: signerPortValue, LocalPort: *localPort,
	})
	if err != nil {
		return err
	}
	data, err := endpointrefs.Marshal(envelope)
	if err != nil {
		return err
	}
	if strings.TrimSpace(*outPath) == "" {
		_, err := c.Streams.Stdout.Write(data)
		return err
	}
	if err := fsutil.WriteFileDurableWithProfile(*outPath, data, fsutil.PrivateStoreFileProfile); err != nil {
		return fmt.Errorf("failed to write endpoint envelope: %w", err)
	}
	c.info("endpoint envelope written: %s", *outPath)
	return nil
}

func (c Catalog) loadEndpointSettings() (endpointExportSettings, error) {
	var settings protocol.AdminSettingsMessage
	if err := c.Client.Request(protocol.GetAdminSettingsMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeGetAdminSettings, ID: c.requestID("endpoint-export-settings")},
	}, &settings); err != nil {
		return endpointExportSettings{}, fmt.Errorf("load endpoint export settings: %w", err)
	}
	return endpointExportSettings{AdvertiseURL: settings.EndpointAdvertiseURL, SSHPort: settings.SSHPort, SignerPort: settings.SignerPort}, nil
}

func (c Catalog) runGenerations(args []string) error {
	if len(args) != 1 || args[0] != "list" {
		return fmt.Errorf("usage: apadmin generations list")
	}
	result, err := requestInspectionWithRetry(c, func() any {
		return protocol.ListGenerationsMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeListGenerations, ID: c.requestID("generations-list")},
		}
	}, func(result *protocol.GenerationsListMessage) string { return result.Code })
	if err != nil {
		return err
	}
	if result.Error != "" {
		return resultError("generation list failed", result.Code, result.Error)
	}
	for _, attempt := range result.PendingAttempts {
		c.info("uncommitted generation %s (discarded at next unlock or prune)", attempt)
	}
	for _, staging := range result.PendingStaging {
		c.info("staging residue %s (discarded at next unlock or prune)", staging)
	}
	if result.RetainedUnsealedParent != "" {
		c.warn("rollback parent %s is missing its seal; pruning is blocked until it is restored or removed", result.RetainedUnsealedParent)
	}
	c.info("current: %s", result.Current)
	for _, prior := range result.SealedPriors {
		c.info("sealed prior: %s", prior)
	}
	if len(result.SealedPriors) == 0 && result.RetainedUnsealedParent == "" {
		c.info("no prior generations (rotation quiescence satisfied)")
	}
	return nil
}

func requestInspectionWithRetry[T any](c Catalog, build func() any, resultCode func(*T) string) (T, error) {
	deadline := c.Now().Add(DefaultTimeout)
	for {
		var result T
		remaining := deadline.Sub(c.Now())
		if remaining <= 0 {
			return result, protocol.WithCode(protocol.ResultCodeStoreBusy, fmt.Errorf("store remained busy during read-only inspection"))
		}
		if err := c.Client.RequestWithTimeout(build(), &result, remaining); err != nil {
			return result, err
		}
		if resultCode(&result) != protocol.ResultCodeStoreBusy {
			return result, nil
		}
		wait := inspectionRetryInterval
		if remaining < wait {
			wait = remaining
		}
		if wait <= 0 {
			return result, protocol.WithCode(protocol.ResultCodeStoreBusy, fmt.Errorf("store remained busy during read-only inspection"))
		}
		c.Sleep(wait)
	}
}

func (c Catalog) requestID(prefix string) string {
	return fmt.Sprintf("apadmin-%s-%d", prefix, c.Now().UnixNano())
}

func (c Catalog) info(format string, args ...any) {
	_, _ = fmt.Fprintf(c.Streams.Stderr, format+"\n", args...)
}

func (c Catalog) warn(format string, args ...any) {
	_, _ = fmt.Fprintf(c.Streams.Stderr, "warning: "+format+"\n", args...)
}

func resultError(prefix, code, message string) error {
	if message == "" {
		message = "operation failed"
	}
	return protocol.WithCode(code, fmt.Errorf("%s: %s", prefix, message))
}

func canonicalKeyType(keyType string) string { return keytypecatalog.Canonicalize(keyType) }
func displayKeyType(keyType string) string   { return keytypefmt.Display(keyType) }

func templateUsesDefaultOpcodeCeiling(templateYAML []byte) bool {
	var header struct {
		MaxOpcodeCost *uint64 `yaml:"max_opcode_cost"`
	}
	return yaml.Unmarshal(templateYAML, &header) == nil && header.MaxOpcodeCost == nil
}

func endpointExportURL(host, explicitURL, advertisedURL string, sshPort int) (string, error) {
	if explicitURL = strings.TrimSpace(explicitURL); explicitURL != "" {
		return explicitURL, nil
	}
	if host = strings.TrimSpace(host); host != "" {
		if strings.Contains(host, "://") {
			return "", fmt.Errorf("--host must be a host or IP without a URL scheme; use --url for explicit endpoint URLs")
		}
		if _, _, err := net.SplitHostPort(host); err == nil {
			return "", fmt.Errorf("--host must not include a port; use --url for custom SSH ports")
		}
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
		}
		return "ssh://" + net.JoinHostPort(host, strconv.Itoa(sshPort)), nil
	}
	if advertisedURL = strings.TrimSpace(advertisedURL); advertisedURL != "" {
		return advertisedURL, nil
	}
	return "", fmt.Errorf("endpoint advertise_url is not configured; pass --host/--url or configure endpoint.advertise_url")
}

func endpointExportUsesSSH(rawURL string) bool {
	return strings.HasPrefix(strings.TrimSpace(strings.ToLower(rawURL)), "ssh://")
}

func endpointExportSSHPort(settings endpointExportSettings) int {
	if settings.SSHPort != 0 {
		return settings.SSHPort
	}
	return apconfig.DefaultSSHPort
}

func endpointExportSignerPort(settings endpointExportSettings) int {
	if settings.SignerPort != 0 {
		return settings.SignerPort
	}
	return apconfig.DefaultRESTPort
}
