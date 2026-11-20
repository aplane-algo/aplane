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
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/witness"

	"gopkg.in/yaml.v3"
)

const inspectionRetryInterval = 100 * time.Millisecond

// Requester is the correlated request seam used by live-admin workflows.
type Requester interface {
	Request(message, result any) error
	RequestWithTimeout(message, result any, timeout time.Duration) error
}

// Streams separates machine output from prompts and status.
type Streams struct {
	Stdin  io.Reader
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
	if s.Stdin == nil {
		s.Stdin = strings.NewReader("")
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

// catalogCommand is one parsed catalog command line: the session it needs,
// whether it reads its input from stdin, and the work Run does for it.
type catalogCommand struct {
	mode       AuthMode
	readsStdin bool
	run        func(Catalog) error
}

func readOnlyCommand(run func(Catalog) error) catalogCommand {
	return catalogCommand{mode: AuthReadOnly, run: run}
}

func unlockedCommand(run func(Catalog) error) catalogCommand {
	return catalogCommand{mode: AuthUnlock, run: run}
}

// CatalogCommands names every command Run accepts. cmd/apadmin routes each of
// them; a test keeps the two lists in step.
var CatalogCommands = []string{
	"template", "keytype", "cosigner", "asa", "clients", "endpoint", "generations", "archive",
}

// parseCatalogCommand is the one grammar of the catalog commands.
// CatalogAuthMode and CatalogReadsStdin consult it before a connection or a
// passphrase prompt, and Run dispatches on what it returns.
func parseCatalogCommand(command string, args []string) (catalogCommand, error) {
	switch command {
	case "template":
		return parseTemplate(args)
	case "keytype":
		return parseKeyType(args)
	case "cosigner":
		return parseCosigner(args)
	case "asa":
		return parseASA(args)
	case "clients":
		return parseClients(args)
	case "endpoint":
		return parseEndpoint(args)
	case "generations":
		return parseGenerations(args)
	case "archive":
		return parseArchive(args)
	}
	return catalogCommand{}, fmt.Errorf("unknown apadmin command %q", command)
}

// CatalogReadsStdin reports whether a catalog command reads its input from
// stdin, which it does for an import whose path is "-". The caller must then
// take the passphrase from somewhere else. A malformed command reads nothing.
func CatalogReadsStdin(command string, args []string) bool {
	cmd, err := parseCatalogCommand(command, args)
	return err == nil && cmd.readsStdin
}

// CatalogAuthMode returns the lock-state behavior required by a catalog
// command. It parses with Run's grammar, so a malformed command is refused
// before a connection or passphrase prompt.
func CatalogAuthMode(command string, args []string) (AuthMode, error) {
	cmd, err := parseCatalogCommand(command, args)
	if err != nil {
		return AuthUnlock, err
	}
	return cmd.mode, nil
}

// Run executes one catalog command using an already authenticated client.
func (c Catalog) Run(command string, args []string) error {
	c = c.normalized()
	if c.Client == nil {
		return fmt.Errorf("admin requester is required")
	}
	cmd, err := parseCatalogCommand(command, args)
	if err != nil {
		return err
	}
	return cmd.run(c)
}

const templateUsage = "usage: apadmin template <list|show|import|remove>"

// parseTemplate parses a template command; every one needs an unlocked
// signer.
func parseTemplate(args []string) (catalogCommand, error) {
	if len(args) == 0 {
		return catalogCommand{}, errors.New(templateUsage)
	}
	switch args[0] {
	case "list":
		if len(args) != 1 {
			return catalogCommand{}, errors.New("usage: apadmin template list")
		}
		return unlockedCommand(Catalog.listTemplates), nil
	case "show":
		if len(args) != 3 || args[2] != "--show-sensitive-template" {
			return catalogCommand{}, errors.New("usage: apadmin template show <key-type> --show-sensitive-template")
		}
		keyType := args[1]
		return unlockedCommand(func(c Catalog) error { return c.showTemplate(keyType) }), nil
	case "import":
		if len(args) != 2 {
			return catalogCommand{}, errors.New("usage: apadmin template import <yaml-file>")
		}
		path := args[1]
		return unlockedCommand(func(c Catalog) error { return c.importTemplate(path) }), nil
	case "remove":
		if len(args) != 2 {
			return catalogCommand{}, errors.New("usage: apadmin template remove <key-type>")
		}
		keyType := args[1]
		return unlockedCommand(func(c Catalog) error { return c.removeTemplate(keyType) }), nil
	}
	return catalogCommand{}, errors.New(templateUsage)
}

// parseKeyType parses enabling or disabling one key type.
func parseKeyType(args []string) (catalogCommand, error) {
	if len(args) != 2 || (args[0] != "enable" && args[0] != "disable") {
		return catalogCommand{}, errors.New("usage: apadmin keytype <enable|disable> <key-type>")
	}
	keyType := canonicalKeyType(args[1])
	if args[0] == "enable" {
		return unlockedCommand(func(c Catalog) error { return c.enableKeyType(keyType) }), nil
	}
	return unlockedCommand(func(c Catalog) error { return c.disableKeyType(keyType) }), nil
}

const cosignerUsage = "usage: apadmin cosigner <export|import|list|show|remove>"

// parseCosigner parses a cosigner command. Exporting, listing and showing
// are public reads; importing and removing change the registry.
func parseCosigner(args []string) (catalogCommand, error) {
	if len(args) == 0 {
		return catalogCommand{}, errors.New(cosignerUsage)
	}
	switch args[0] {
	case "export":
		if len(args) < 2 || len(args) > 3 {
			return catalogCommand{}, errors.New("usage: apadmin cosigner export <cosigner-key-id> [output-json]")
		}
		exportArgs := args[1:]
		return readOnlyCommand(func(c Catalog) error { return c.exportCosigner(exportArgs) }), nil
	case "list":
		if len(args) != 1 {
			return catalogCommand{}, errors.New("usage: apadmin cosigner list")
		}
		return readOnlyCommand(Catalog.listCosigners), nil
	case "show":
		if len(args) != 2 {
			return catalogCommand{}, errors.New("usage: apadmin cosigner show <name>")
		}
		name := args[1]
		return readOnlyCommand(func(c Catalog) error { return c.showCosigner(name) }), nil
	case "import":
		// The public key envelope's path, "-" for stdin, and the cosigner's
		// name.
		if len(args) != 3 {
			return catalogCommand{}, errors.New("usage: apadmin cosigner import <public-json|-> <name>")
		}
		path, name := args[1], args[2]
		cmd := unlockedCommand(func(c Catalog) error { return c.importCosigner(path, name) })
		cmd.readsStdin = path == "-"
		return cmd, nil
	case "remove":
		if len(args) != 2 {
			return catalogCommand{}, errors.New("usage: apadmin cosigner remove <name>")
		}
		name := args[1]
		return unlockedCommand(func(c Catalog) error { return c.removeCosigner(name) }), nil
	}
	return catalogCommand{}, errors.New(cosignerUsage)
}

const endpointExportUsage = "usage: apadmin endpoint export [--host <host> | --url <url>] [--out endpoint.json]"

// parseEndpoint parses an endpoint export, a public read.
func parseEndpoint(args []string) (catalogCommand, error) {
	if len(args) == 0 || args[0] != "export" {
		return catalogCommand{}, errors.New("usage: apadmin endpoint <export>")
	}
	fs := flag.NewFlagSet("apadmin endpoint export", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	host := fs.String("host", "", "client-reachable SSH host or IP")
	endpointURL := fs.String("url", "", "endpoint URL")
	outPath := fs.String("out", "", "output JSON path")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
		return catalogCommand{}, errors.New(endpointExportUsage)
	}
	return readOnlyCommand(func(c Catalog) error { return c.exportEndpoint(*host, *endpointURL, *outPath) }), nil
}

const generationsUsage = "usage: apadmin generations <list|prune|discard>"

// parseGenerations parses a generations command. Listing is a public read;
// pruning and discarding delete store data.
func parseGenerations(args []string) (catalogCommand, error) {
	if len(args) == 0 {
		return catalogCommand{}, errors.New(generationsUsage)
	}
	switch args[0] {
	case "list":
		if len(args) == 1 {
			return readOnlyCommand(Catalog.listGenerations), nil
		}
	case "prune":
		confirm, ids, err := parseConfirmedList("generations prune", "<generation-id> [generation-id...]", args[1:])
		if err != nil {
			return catalogCommand{}, err
		}
		return unlockedCommand(func(c Catalog) error { return c.pruneGenerationQuarantine(confirm, ids) }), nil
	case "discard":
		confirm, ids, err := parseConfirmedList("generations discard", "<generation-id> [generation-id...]", args[1:])
		if err != nil {
			return catalogCommand{}, err
		}
		return unlockedCommand(func(c Catalog) error { return c.discardAbandonedGenerations(confirm, ids) }), nil
	}
	return catalogCommand{}, errors.New(generationsUsage)
}

// parseArchive parses an archive command. The daemon serves the archive
// listing only to an unlocked or recovery-admin session, never to an
// auth_only observer, so listing unlocks too.
func parseArchive(args []string) (catalogCommand, error) {
	if len(args) == 1 && args[0] == "list" {
		return unlockedCommand(Catalog.listArchive), nil
	}
	if len(args) > 0 && args[0] == "prune" {
		confirm, entries, err := parseConfirmedList("archive prune", "<deleted/path> [deleted/path...]", args[1:])
		if err != nil {
			return catalogCommand{}, err
		}
		return unlockedCommand(func(c Catalog) error { return c.pruneArchive(confirm, entries) }), nil
	}
	return catalogCommand{}, errors.New("usage: apadmin archive <list|prune>")
}

// parseConfirmedList parses a verb that takes --confirm and at least one
// operand, such as "generations prune".
func parseConfirmedList(verb, operands string, args []string) (confirm bool, list []string, err error) {
	fs := flag.NewFlagSet("apadmin "+verb, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	confirmFlag := fs.Bool("confirm", false, "confirm the irreversible deletion")
	if err := fs.Parse(args); err != nil || fs.NArg() == 0 {
		return false, nil, fmt.Errorf("usage: apadmin %s --confirm %s", verb, operands)
	}
	return *confirmFlag, append([]string(nil), fs.Args()...), nil
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
		_, _ = fmt.Fprintf(c.Streams.Stdout, "  %s  (%s, %s, %s)\n", item.KeyType, backup.FormatFileSize(item.Size), item.TemplateType, status)
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
	c.info("template: %s (%s)", result.KeyType, result.TemplateType)
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
		c.info("%s template %s is already installed", result.TemplateType, result.KeyType)
		return nil
	}
	if templateUsesDefaultOpcodeCeiling(templateYAML) {
		c.warn("template declares no max_opcode_cost; using the compiled v42 single-group-member opcode ceiling (%d) for each applicable authorization path", lsigresource.SingleTransactionOpcodeCeiling)
	}
	c.info("%s template %s imported", result.TemplateType, result.KeyType)
	return nil
}

func (c Catalog) removeTemplate(keyType string) error {
	keyType = canonicalKeyType(keyType)
	if !c.Confirm(fmt.Sprintf("Remove installed template %s? [y/N]: ", keyType)) {
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
		c.info("template %s removed", result.KeyType)
	} else {
		c.info("template %s was already absent", result.KeyType)
	}
	return nil
}

func (c Catalog) enableKeyType(keyType string) error {
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
		c.info("key type %s was already enabled", result.KeyType)
	} else {
		c.info("key type %s enabled", result.KeyType)
	}
	return nil
}

func (c Catalog) disableKeyType(keyType string) error {
	if !c.Confirm(fmt.Sprintf("Disable key type %s? [y/N]: ", keyType)) {
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
		c.info("key type %s disabled", result.KeyType)
	} else {
		c.info("key type %s was already disabled", result.KeyType)
	}
	return nil
}

func (c Catalog) exportCosigner(args []string) error {
	keyID, err := witness.NormalizeID(args[0])
	if err != nil {
		return fmt.Errorf("invalid Witness Key ID: %w", err)
	}
	result, err := requestInspectionWithRetry(c, func() any {
		return protocol.ExportCosignerPublicMessage{
			BaseMessage:  protocol.BaseMessage{Type: protocol.MsgTypeExportCosignerPublic, ID: c.requestID("cosigner-export")},
			WitnessKeyID: keyID,
		}
	}, func(result *protocol.ExportCosignerPublicResultMessage) string { return result.Code })
	if err != nil {
		return err
	}
	if !result.Success {
		return resultError("cosigner export failed", result.Code, result.Error)
	}
	data := []byte(result.EnvelopeJSON)
	if len(args) == 1 {
		_, err := c.Streams.Stdout.Write(data)
		return err
	}
	if err := WriteCosignerPublicEnvelope(args[1], data); err != nil {
		return err
	}
	c.info("cosigner public key envelope written: %s", args[1])
	return nil
}

func (c Catalog) importCosigner(path, name string) error {
	data, err := ReadCosignerPublicEnvelope(path, c.Streams.Stdin)
	if err != nil {
		return err
	}
	// The file is the cosigner's public key and nothing else; the signer
	// stores its canonical form.
	reference, err := witness.ParsePublicReference(data)
	if err != nil {
		return err
	}
	data, err = witness.MarshalPublicReference(reference)
	if err != nil {
		return err
	}
	var result protocol.ImportCosignerReferenceResultMessage
	if err := c.Client.Request(protocol.ImportCosignerReferenceMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeImportCosignerReference, ID: c.requestID("cosigner-import")},
		Name:        name, EnvelopeJSON: string(data),
	}, &result); err != nil {
		return err
	}
	if !result.Success {
		return resultError("cosigner import failed", result.Code, result.Error)
	}
	c.info("cosigner reference %s imported for %s", result.Reference.Name, result.Reference.KeyType)
	return nil
}

func (c Catalog) listCosigners() error {
	result, err := requestInspectionWithRetry(c, func() any {
		return protocol.ListCosignerReferencesMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeListCosignerReferences, ID: c.requestID("cosigner-list")},
		}
	}, func(result *protocol.CosignerReferencesListMessage) string { return result.Code })
	if err != nil {
		return err
	}
	if result.Error != "" {
		return resultError("cosigner list failed", result.Code, result.Error)
	}
	if len(result.References) == 0 && len(result.Invalid) == 0 {
		c.info("no cosigner references found")
		return nil
	}
	c.info("found %d cosigner reference(s)", len(result.References))
	for _, record := range result.References {
		label := "unknown"
		if record.Name != "" {
			label = record.Name
		}
		_, _ = fmt.Fprintf(c.Streams.Stdout, "  %s  %s  (%s)\n", label, CompactWitnessKeyID(record.ComponentKey), record.KeyType)
	}
	for _, bad := range result.Invalid {
		if bad.Removable {
			c.warn("%q is not a valid cosigner reference: %s; clear it with: apadmin cosigner remove %s", bad.Path, bad.Reason, bad.Name)
		} else {
			c.warn("%q is not a valid cosigner reference: %s; apadmin cosigner remove does not reach it, so delete the file to clear it", bad.Path, bad.Reason)
		}
	}
	return nil
}

func (c Catalog) showCosigner(name string) error {
	result, err := requestInspectionWithRetry(c, func() any {
		return protocol.GetCosignerReferenceMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeGetCosignerReference, ID: c.requestID("cosigner-show")},
			Name:        name,
		}
	}, func(result *protocol.CosignerReferenceMessage) string { return result.Code })
	if err != nil {
		return err
	}
	if !result.Success {
		return resultError("cosigner show failed", result.Code, result.Error)
	}
	data, err := json.MarshalIndent(result.Reference, "", "  ")
	if err != nil {
		return fmt.Errorf("encode cosigner reference: %w", err)
	}
	_, err = c.Streams.Stdout.Write(append(data, '\n'))
	return err
}

func (c Catalog) removeCosigner(name string) error {
	var result protocol.RemoveCosignerReferenceResultMessage
	if err := c.Client.Request(protocol.RemoveCosignerReferenceMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeRemoveCosignerReference, ID: c.requestID("cosigner-remove")},
		Name:        name,
	}, &result); err != nil {
		return err
	}
	if !result.Success {
		return resultError("cosigner remove failed", result.Code, result.Error)
	}
	if result.Removed {
		c.info("cosigner reference %s removed: deleted %q", name, result.Path)
	} else {
		c.info("cosigner reference %s was already absent", name)
	}
	return nil
}

type endpointExportSettings struct {
	AdvertiseURL string
	SSHPort      int
}

func (c Catalog) exportEndpoint(host, endpointURL, outPath string) error {
	settings, err := c.loadEndpointSettings()
	if err != nil {
		return err
	}
	envelope, err := buildEndpointExportEnvelope(host, endpointURL, settings)
	if err != nil {
		return err
	}
	data, err := endpointrefs.Marshal(envelope)
	if err != nil {
		return err
	}
	if strings.TrimSpace(outPath) == "" {
		_, err := c.Streams.Stdout.Write(data)
		return err
	}
	if err := fsutil.WriteFileDurable(outPath, data); err != nil {
		return fmt.Errorf("failed to write endpoint envelope: %w", err)
	}
	c.info("endpoint envelope written: %s", outPath)
	return nil
}

func buildEndpointExportEnvelope(host, explicitURL string, settings endpointExportSettings) (endpointrefs.Envelope, error) {
	urlValue, err := endpointExportURL(host, explicitURL, settings.AdvertiseURL, endpointExportSSHPort(settings))
	if err != nil {
		return endpointrefs.Envelope{}, err
	}
	return endpointrefs.Normalize(endpointrefs.Envelope{Schema: endpointrefs.Schema, URL: urlValue})
}

func (c Catalog) loadEndpointSettings() (endpointExportSettings, error) {
	var settings protocol.AdminSettingsMessage
	if err := c.Client.Request(protocol.GetAdminSettingsMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeGetAdminSettings, ID: c.requestID("endpoint-export-settings")},
	}, &settings); err != nil {
		return endpointExportSettings{}, fmt.Errorf("load endpoint export settings: %w", err)
	}
	return endpointExportSettings{AdvertiseURL: settings.EndpointAdvertiseURL, SSHPort: settings.SSHPort}, nil
}

func (c Catalog) listGenerations() error {
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
	for _, item := range result.Quarantined {
		c.info(
			"quarantined generation %s (bytes=%d entries=%d at_mint_match=%t term_verified=%d term_unavailable=%d term_failed=%d)",
			item.GenerationID,
			item.EncodedBytes,
			item.EntryCount,
			item.AtMintInventoryMatch,
			item.TermVerified,
			item.TermUnavailable,
			item.TermFailed,
		)
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
		c.info("no prior generations")
	}
	return nil
}

func (c Catalog) discardAbandonedGenerations(confirm bool, generationIDs []string) error {
	var result protocol.DiscardAbandonedGenerationsResultMessage
	if err := c.Client.Request(protocol.DiscardAbandonedGenerationsMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeDiscardAbandonedGenerations,
			ID:   c.requestID("generation-abandoned-discard"),
		},
		GenerationIDs: generationIDs, Confirm: confirm,
	}, &result); err != nil {
		return err
	}
	if !result.Success {
		return resultError("abandoned generation discard failed", result.Code, result.Error)
	}
	for _, item := range result.Discarded {
		if item.AlreadyAbsent {
			c.info("abandoned generation %s already absent", item.GenerationID)
		} else {
			c.info("discarded abandoned generation %s (%d bytes)", item.GenerationID, item.EncodedBytes)
		}
	}
	return nil
}

func (c Catalog) pruneGenerationQuarantine(confirm bool, generationIDs []string) error {
	var result protocol.PruneGenerationQuarantineResultMessage
	if err := c.Client.Request(protocol.PruneGenerationQuarantineMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypePruneGenerationQuarantine,
			ID:   c.requestID("generation-quarantine-prune"),
		},
		GenerationIDs: generationIDs,
		Confirm:       confirm,
	}, &result); err != nil {
		return err
	}
	if !result.Success {
		return resultError("generation quarantine prune failed", result.Code, result.Error)
	}
	for _, item := range result.Pruned {
		if item.AlreadyAbsent {
			c.info("quarantined generation %s already absent", item.GenerationID)
			continue
		}
		c.info("pruned quarantined generation %s (%d bytes)", item.GenerationID, item.EncodedBytes)
	}
	return nil
}

func (c Catalog) listArchive() error {
	result, err := requestInspectionWithRetry(c, func() any {
		return protocol.ListDeletedArchiveMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeListDeletedArchive, ID: c.requestID("archive-list")},
		}
	}, func(result *protocol.DeletedArchiveListMessage) string { return result.Code })
	if err != nil {
		return err
	}
	if result.Error != "" {
		return resultError("archive list failed", result.Code, result.Error)
	}
	for _, item := range result.Entries {
		c.info("archived %s (%d bytes)", item.Path, item.EncodedBytes)
	}
	c.info("deleted archive: %d entries, %d encoded bytes", result.EntryCount, result.EncodedBytes)
	if result.Warning {
		c.warn("deleted archive emergency-deletion reserve is consumed; prune before the next incident-response deletion")
	}
	return nil
}

func (c Catalog) pruneArchive(confirm bool, entries []string) error {
	var result protocol.PruneDeletedArchiveResultMessage
	if err := c.Client.Request(protocol.PruneDeletedArchiveMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypePruneDeletedArchive, ID: c.requestID("archive-prune")},
		Entries:     entries, Confirm: confirm,
	}, &result); err != nil {
		return err
	}
	if !result.Success {
		return resultError("archive prune failed", result.Code, result.Error)
	}
	for _, item := range result.Pruned {
		if item.AlreadyAbsent {
			c.info("archive entry %s already absent", item.Path)
		} else {
			c.info("pruned archive entry %s (%d bytes)", item.Path, item.EncodedBytes)
		}
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
		c.Sleep(min(inspectionRetryInterval, remaining))
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

func endpointExportSSHPort(settings endpointExportSettings) int {
	if settings.SSHPort != 0 {
		return settings.SSHPort
	}
	return apconfig.DefaultSSHPort
}
