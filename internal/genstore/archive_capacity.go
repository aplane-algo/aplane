// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package genstore

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// Deleted-archive limits are part of the store layout contract. They must not
// be lowered without a new layout version and an explicit recovery contract.
// The warning threshold reserves one entry and one maximum-sized envelope for
// an incident-response deletion.
const (
	DeletedArchiveMaxEntries       = 4_096
	DeletedArchiveMaxEncodedBytes  = 256 << 20
	DeletedArchiveWarnEntries      = DeletedArchiveMaxEntries - 1
	DeletedArchiveWarnEncodedBytes = DeletedArchiveMaxEncodedBytes - crypto.MaxStandaloneEnvelopeBytes
)

// DeletedArchiveUsage is the exact encoded occupancy of the selected
// generation's credential and template tombstone namespaces.
type DeletedArchiveUsage struct {
	Entries      int
	EncodedBytes int64
}

// Warning reports whether the operational reserve for one maximum-sized
// emergency deletion has been consumed.
func (u DeletedArchiveUsage) Warning() bool {
	return u.Entries > DeletedArchiveWarnEntries || u.EncodedBytes > DeletedArchiveWarnEncodedBytes
}

// InspectDeletedArchive returns bounded archive occupancy without opening any
// envelope. It rejects links, directories, oversize members, and hard-limit
// overflow before reading member bytes.
func InspectDeletedArchive(gen storepaths.GenPaths) (DeletedArchiveUsage, error) {
	var usage DeletedArchiveUsage
	for _, dir := range []string{gen.DeletedKeysDir(), gen.DeletedKeyTypeRecordsDir()} {
		info, err := os.Lstat(dir)
		if err != nil {
			return usage, fmt.Errorf("inspect deleted archive: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return usage, fmt.Errorf("deleted archive namespace is not a regular directory: %s", dir)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return usage, fmt.Errorf("inspect deleted archive: %w", err)
		}
		for _, entry := range entries {
			path := filepath.Join(dir, entry.Name())
			member, err := os.Lstat(path)
			if err != nil {
				return usage, fmt.Errorf("inspect deleted archive member: %w", err)
			}
			if member.Mode()&os.ModeSymlink != 0 || !member.Mode().IsRegular() {
				return usage, fmt.Errorf("deleted archive member is not a regular file: %s", path)
			}
			if member.Size() > crypto.MaxStandaloneEnvelopeBytes {
				return usage, fmt.Errorf(
					"deleted archive member %s is %d bytes; maximum is %d",
					path, member.Size(), crypto.MaxStandaloneEnvelopeBytes,
				)
			}
			usage.Entries++
			usage.EncodedBytes += member.Size()
			if err := validateDeletedArchiveUsage(usage); err != nil {
				return usage, err
			}
		}
	}
	return usage, nil
}

// PreflightDeletedArchiveAppend proves that moving candidate into the
// selected archive cannot cross either hard limit. It performs no mutation.
func PreflightDeletedArchiveAppend(gen storepaths.GenPaths, candidate string) (DeletedArchiveUsage, error) {
	usage, err := InspectDeletedArchive(gen)
	if err != nil {
		return usage, err
	}
	info, err := os.Lstat(candidate)
	if err != nil {
		return usage, fmt.Errorf("inspect deletion candidate: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return usage, fmt.Errorf("deletion candidate is not a regular file: %s", candidate)
	}
	if info.Size() > crypto.MaxStandaloneEnvelopeBytes {
		return usage, fmt.Errorf(
			"deletion candidate is %d bytes; maximum managed envelope is %d",
			info.Size(), crypto.MaxStandaloneEnvelopeBytes,
		)
	}
	prospective := DeletedArchiveUsage{
		Entries:      usage.Entries + 1,
		EncodedBytes: usage.EncodedBytes + info.Size(),
	}
	if err := validateDeletedArchiveUsage(prospective); err != nil {
		countDeficit := max(0, prospective.Entries-DeletedArchiveMaxEntries)
		byteDeficit := max(int64(0), prospective.EncodedBytes-DeletedArchiveMaxEncodedBytes)
		return usage, fmt.Errorf(
			"refusing credential deletion before changing active state: deleted archive capacity would be exceeded (entry deficit %d, byte deficit %d); use the authenticated archive prune workflow",
			countDeficit, byteDeficit,
		)
	}
	return prospective, nil
}

func validateDeletedArchiveUsage(usage DeletedArchiveUsage) error {
	if usage.Entries > DeletedArchiveMaxEntries {
		return fmt.Errorf(
			"deleted archive contains %d entries; layout limit is %d; ordinary unlock and generation mint are blocked until authenticated prune",
			usage.Entries, DeletedArchiveMaxEntries,
		)
	}
	if usage.EncodedBytes > DeletedArchiveMaxEncodedBytes {
		return fmt.Errorf(
			"deleted archive contains %d encoded bytes; layout limit is %d; ordinary unlock and generation mint are blocked until authenticated prune",
			usage.EncodedBytes, DeletedArchiveMaxEncodedBytes,
		)
	}
	return nil
}
