// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package cosignerrefs stores product-store public cosigner references used when
// generating cosigned accounts.
package cosignerrefs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/cosigner/keytypes"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/witness"
)

const (
	RecordSchema = "aplane.cosigner-public-key-ref.v3"

	// ParamCosignerName is the generation parameter that selects an imported
	// cosigner reference by name.
	ParamCosignerName = "cosigner"
)

var nameShape = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]*$`)

// ErrInvalidRecord marks a stored reference that does not parse or does not
// hold together. Remove removes one all the same.
var ErrInvalidRecord = errors.New("invalid cosigner reference")

type ExportEnvelope = witness.PublicReference

// Record is a stored cosigner reference. ComponentKey is the Witness Key ID
// KeyType and PublicKeyHex derive; every read checks that it does.
type Record struct {
	Schema       string `json:"schema"`
	Name         string `json:"name"`
	ComponentKey string `json:"component_key"`
	KeyType      string `json:"key_type"`
	PublicKeyHex string `json:"public_key_hex"`
	ImportedAt   string `json:"imported_at"`
}

func NormalizeName(name string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(name))
	if normalized == "" {
		return "", fmt.Errorf("cosigner reference name is required")
	}
	if !nameShape.MatchString(normalized) {
		return "", fmt.Errorf("invalid cosigner reference name %q: use lowercase letters, numbers, '.', '-' and '_'", name)
	}
	if strings.Contains(normalized, "..") {
		return "", fmt.Errorf("invalid cosigner reference name %q: must not contain '..'", name)
	}
	return normalized, nil
}

func NewExportEnvelope(componentKey, keyType, publicKeyHex string) (*ExportEnvelope, error) {
	reference, err := witness.NewPublicReference(keyType, componentKey, strings.ToLower(strings.TrimSpace(publicKeyHex)))
	if err != nil {
		return nil, err
	}
	return &reference, nil
}

func Import(paths storepaths.Paths, name string, data []byte) (*Record, error) {
	record, err := ParseImport(name, data)
	if err != nil {
		return nil, err
	}
	existing, bad, missing := inspect(paths.CosignerRefPath(record.Name), record.Name)
	if bad != nil {
		return nil, fmt.Errorf("cannot import cosigner reference %q over a file that is not a valid reference: %s", record.Name, bad)
	}
	if !missing {
		if sameReferenceAuthority(existing, *record) {
			return &existing, nil
		}
		return nil, fmt.Errorf(
			"cosigner reference %q already exists with Witness Key ID %s; remove it explicitly before importing Witness Key ID %s",
			record.Name, existing.ComponentKey, record.ComponentKey,
		)
	}
	record.ImportedAt = time.Now().UTC().Format(time.RFC3339)
	if err := putRecord(paths, *record); err != nil {
		return nil, err
	}
	return record, nil
}

func sameReferenceAuthority(a, b Record) bool {
	return a.ComponentKey == b.ComponentKey &&
		a.KeyType == b.KeyType &&
		a.PublicKeyHex == b.PublicKeyHex
}

func ParseImport(name string, data []byte) (*Record, error) {
	name, err := NormalizeName(name)
	if err != nil {
		return nil, err
	}
	env, err := witness.ParsePublicReference(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cosigner public-key envelope: %w", err)
	}
	return &Record{
		Schema:       RecordSchema,
		Name:         name,
		ComponentKey: env.WitnessKeyID,
		KeyType:      env.KeyType,
		PublicKeyHex: env.PublicKeyHex,
	}, nil
}

func putRecord(paths storepaths.Paths, rec Record) error {
	normalized, err := normalizeRecord(rec)
	if err != nil {
		return err
	}
	path := paths.CosignerRefPath(normalized.Name)
	if err := fsutil.MkdirAllPrivate(filepath.Dir(path)); err != nil {
		return fmt.Errorf("failed to create cosigner reference directory: %w", err)
	}
	data, err := json.MarshalIndent(normalized, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode cosigner reference: %w", err)
	}
	data = append(data, '\n')
	if err := fsutil.WriteFileDurable(path, data); err != nil {
		return fmt.Errorf("failed to write cosigner reference: %w", err)
	}
	return nil
}

func Get(paths storepaths.Paths, name string) (Record, bool, error) {
	name, err := NormalizeName(name)
	if err != nil {
		return Record{}, false, err
	}
	rec, bad, missing := inspect(paths.CosignerRefPath(name), name)
	switch {
	case missing:
		return Record{}, false, nil
	case bad == nil:
		return rec, true, nil
	case bad.Removable:
		return Record{}, false, fmt.Errorf("%w %s: %s", ErrInvalidRecord, name, bad.Reason)
	default:
		return Record{}, false, fmt.Errorf("cosigner reference %s %s", name, bad.Reason)
	}
}

// InvalidRecord is a ".json" entry of the reference directory that is not a
// valid cosigner reference.
type InvalidRecord struct {
	Path   string // the entry, as it is named in the directory
	Stem   string // its name without ".json"
	Reason string
	// Removable says whether Remove of Stem clears it. Only an entry named for
	// a reference name that Remove can read, or a dangling symlink, is; any
	// other one has to be deleted by hand.
	Removable bool
}

func (r InvalidRecord) String() string {
	if r.Removable {
		return fmt.Sprintf("%q: %s (remove reference %s to clear it)", r.Path, r.Reason, r.Stem)
	}
	return fmt.Sprintf("%q: %s (remove does not reach it; delete the file to clear it)", r.Path, r.Reason)
}

// List returns the valid cosigner references and, beside them, every other
// ".json" entry of the reference directory with why it is not one: one bad
// entry never hides the rest. Only a directory that cannot be read fails the
// list.
func List(paths storepaths.Paths) ([]Record, []InvalidRecord, error) {
	dir := paths.CosignerRefsDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("failed to read cosigner reference directory: %w", err)
	}
	records := make([]Record, 0, len(entries))
	var invalid []InvalidRecord
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		rec, bad := listEntry(dir, entry)
		switch {
		case rec != nil:
			records = append(records, *rec)
		case bad != nil:
			invalid = append(invalid, *bad)
		}
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].Name < records[j].Name
	})
	sort.Slice(invalid, func(i, j int) bool {
		return invalid[i].Path < invalid[j].Path
	})
	return records, invalid, nil
}

// listEntry reads one ".json" entry of the reference directory: a record, or
// the entry as an invalid one, or neither when the entry was removed after
// the directory was read.
func listEntry(dir string, entry os.DirEntry) (*Record, *InvalidRecord) {
	bad := &InvalidRecord{Path: filepath.Join(dir, entry.Name()), Stem: strings.TrimSuffix(entry.Name(), ".json")}
	if name, err := NormalizeName(bad.Stem); err != nil || name != bad.Stem {
		bad.Reason = fmt.Sprintf("%q is not a reference name", bad.Stem)
		return nil, bad
	}
	rec, invalid, missing := inspect(bad.Path, bad.Stem)
	switch {
	case missing && entry.Type()&os.ModeSymlink != 0:
		// Remove reads a dangling symlink as absent and deletes it.
		bad.Reason, bad.Removable = "symlink to a missing file", true
		return nil, bad
	case missing:
		return nil, nil
	case invalid != nil:
		return nil, invalid
	}
	return &rec, nil
}

// inspect reads the reference file at path, named stem: the record, or the
// file as an invalid one, or missing when nothing is there, a dangling
// symlink included. A directory, a FIFO or another special file is refused
// by its type and never read. Remove reads the record first, so a file this
// cannot read is not removable.
func inspect(path, stem string) (Record, *InvalidRecord, bool) {
	bad := &InvalidRecord{Path: path, Stem: stem}
	info, err := os.Stat(path)
	switch {
	case os.IsNotExist(err):
		return Record{}, nil, true
	case err != nil:
		bad.Reason = "cannot be inspected: " + errorCause(err)
	case info.IsDir():
		bad.Reason = "is a directory"
	case !info.Mode().IsRegular():
		bad.Reason = "is not a regular file"
	}
	if bad.Reason != "" {
		return Record{}, bad, false
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Record{}, nil, true
	}
	if err != nil {
		bad.Reason = "cannot be read: " + errorCause(err)
		return Record{}, bad, false
	}
	rec, err := parseRecord(data, stem)
	if err != nil {
		bad.Reason, bad.Removable = boundedReason(err.Error()), true
		return Record{}, bad, false
	}
	return rec, nil, false
}

// maxReasonBytes bounds a reason, which can quote a value read from the file,
// so a listing stays far below the admin frame limit.
const maxReasonBytes = 200

func boundedReason(reason string) string {
	if len(reason) <= maxReasonBytes {
		return reason
	}
	cut := maxReasonBytes
	for cut > 0 && !utf8.RuneStart(reason[cut]) {
		cut--
	}
	return reason[:cut] + "...(truncated)"
}

// errorCause drops the path a filesystem error repeats: the entry names it.
func errorCause(err error) string {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err.Error()
	}
	return err.Error()
}

// Removal is what Remove did.
type Removal struct {
	Removed      bool
	ComponentKey string // the removed reference's Witness Key ID, when its record parsed
	Path         string // the file deleted
}

// Remove deletes the reference named name. The name must be a reference name
// exactly as listed: a near miss such as "Foo" would name the file of another
// reference, "foo", so it is refused. A record that does not parse is removed
// all the same, which is how the operator clears one the list reports.
func Remove(paths storepaths.Paths, name string) (Removal, error) {
	canonical, err := NormalizeName(name)
	if err != nil {
		return Removal{}, err
	}
	if canonical != name {
		return Removal{}, fmt.Errorf("remove takes a reference name exactly as listed: %q would be the reference %q, stored as %q, not %q",
			name, canonical, canonical+".json", name+".json")
	}
	existing, found, err := Get(paths, name)
	if err != nil && !errors.Is(err, ErrInvalidRecord) {
		return Removal{}, err
	}
	path := paths.CosignerRefPath(name)
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return Removal{}, nil
		}
		return Removal{}, fmt.Errorf("failed to remove cosigner reference %s: %w", name, err)
	}
	removal := Removal{Removed: true, Path: path}
	if found {
		removal.ComponentKey = existing.ComponentKey
	}
	return removal, nil
}

// ResolveCreationParamsForComponents resolves the signer-facing cosigner
// selector for any provider that declares the cosigner component types it
// takes. The reference must be one of them. Its public key replaces the
// selector, and its type, when it is not the default, is recorded beside it; a
// type the request already gives must agree. This keeps generic
// bounded-cosigner templates out of hard-coded cosigned-account key-type tables.
func ResolveCreationParamsForComponents(paths storepaths.Paths, keyType string, componentKeyTypes []string, params map[string]string) (map[string]string, error) {
	selector, hasSelector := params[ParamCosignerName]
	if !hasSelector || strings.TrimSpace(selector) == "" {
		return params, nil
	}
	if _, hasPublicKey := params[keytypes.ParameterCosignerPublicKey]; hasPublicKey {
		return nil, fmt.Errorf("specify either %s or %s, not both", ParamCosignerName, keytypes.ParameterCosignerPublicKey)
	}
	rec, ok, err := resolveByNameOrComponentKey(paths, selector)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("cosigner reference or Witness Key ID %q not found", strings.TrimSpace(selector))
	}
	if !slices.Contains(componentKeyTypes, rec.KeyType) {
		return nil, fmt.Errorf("cosigner reference %q uses %s, but %s takes %s", rec.Name, rec.KeyType, keyType, strings.Join(componentKeyTypes, " or "))
	}
	// An empty value is the provider's to refuse, with its own message.
	if given := strings.TrimSpace(params[boundedmeta.CosignerKeyTypeParameter]); given != "" && given != rec.KeyType {
		return nil, fmt.Errorf("%s %s contradicts cosigner reference %q, which uses %s", boundedmeta.CosignerKeyTypeParameter, given, rec.Name, rec.KeyType)
	}

	resolved := make(map[string]string, len(params))
	for k, v := range params {
		if k == ParamCosignerName {
			continue
		}
		resolved[k] = v
	}
	resolved[keytypes.ParameterCosignerPublicKey] = rec.PublicKeyHex
	if rec.KeyType != boundedmeta.DefaultCosignerComponentKeyType {
		resolved[boundedmeta.CosignerKeyTypeParameter] = rec.KeyType
	}
	return resolved, nil
}

func resolveByNameOrComponentKey(paths storepaths.Paths, value string) (Record, bool, error) {
	value = strings.TrimSpace(value)
	if componentKey, err := witness.NormalizeID(value); err == nil {
		records, invalid, err := List(paths)
		if err != nil {
			return Record{}, false, err
		}
		for _, rec := range records {
			if rec.ComponentKey == componentKey {
				return rec, true, nil
			}
		}
		// The reference sought may be one that cannot be read.
		if len(invalid) > 0 {
			described := make([]string, len(invalid))
			for i, bad := range invalid {
				// A REST client gets this error: it names each entry by its
				// file name, not by its path on the signer.
				described[i] = fmt.Sprintf("%q: %s", filepath.Base(bad.Path), bad.Reason)
			}
			return Record{}, false, fmt.Errorf("%w: no valid cosigner reference has Witness Key ID %s, and these reference files are not valid: %s",
				ErrInvalidRecord, componentKey, strings.Join(described, "; "))
		}
		return Record{}, false, nil
	}
	return Get(paths, value)
}

func parseRecord(data []byte, expectedName string) (Record, error) {
	// The schema is read first, so a record of another schema is reported as
	// that, not as the fields its shape carries.
	var header struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return Record{}, fmt.Errorf("failed to parse record: %w", err)
	}
	if header.Schema != RecordSchema {
		return Record{}, fmt.Errorf("unsupported schema %q", header.Schema)
	}
	var rec Record
	if err := decodeRecordStrict(data, &rec); err != nil {
		return Record{}, err
	}
	rec, err := normalizeRecord(rec)
	if err != nil {
		return Record{}, err
	}
	if rec.Name != expectedName {
		return Record{}, fmt.Errorf("record name %q does not match filename %q", rec.Name, expectedName)
	}
	return rec, nil
}

func decodeRecordStrict(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("failed to parse record: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("failed to parse record: multiple JSON values")
		}
		return fmt.Errorf("failed to parse record: %w", err)
	}
	return nil
}

func normalizeRecord(rec Record) (Record, error) {
	name, err := NormalizeName(rec.Name)
	if err != nil {
		return Record{}, err
	}
	env, err := witness.NewPublicReference(rec.KeyType, rec.ComponentKey, rec.PublicKeyHex)
	if err != nil {
		return Record{}, err
	}
	// Import stamps every record before it is written.
	if _, err := time.Parse(time.RFC3339, rec.ImportedAt); err != nil {
		return Record{}, fmt.Errorf("imported_at %q is not an RFC 3339 time", rec.ImportedAt)
	}
	return Record{
		Schema:       RecordSchema,
		Name:         name,
		ComponentKey: env.WitnessKeyID,
		KeyType:      env.KeyType,
		PublicKeyHex: env.PublicKeyHex,
		ImportedAt:   rec.ImportedAt,
	}, nil
}
