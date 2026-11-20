// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policycmd

import (
	"fmt"
	"os"

	signerbootstrap "github.com/aplane-algo/aplane/internal/bootstrap/signer"
	"github.com/aplane-algo/aplane/internal/storelock"
	"github.com/aplane-algo/aplane/internal/storeperm"
)

var (
	EffectiveUID      = os.Geteuid
	IsManagedStore    = signerbootstrap.IsProductionManagedDataDir
	ManagedStoreOwner = storeperm.ManagedServiceOwner
	AcquireStoreLock  = storelock.AcquireExclusive
	NormalizeStore    = func(dataDir string, uid, gid int) error {
		_, err := storeperm.MigratePrivate(storeperm.RepairMigrationOptions(dataDir, uid, gid))
		return err
	}
)

type OfflineMutation struct {
	dataDir string
	uid     int
	gid     int
	lock    *storelock.Guard
	managed bool
}

func AcquireOfflineMutation(dataDir string) (*OfflineMutation, error) {
	if dataDir == "" {
		return nil, fmt.Errorf("signer data directory is required for policy rescue mutation")
	}
	lock, err := AcquireStoreLock(dataDir)
	if err != nil {
		return nil, fmt.Errorf("acquire exclusive signer-store lock before editing (stop apsigner and other store-mutating tools): %w", err)
	}
	guard := &OfflineMutation{dataDir: dataDir, lock: lock}
	if EffectiveUID() != 0 {
		return guard, nil
	}
	managed, err := IsManagedStore(dataDir)
	if err != nil {
		guard.Close()
		return nil, err
	}
	if !managed {
		return guard, nil
	}
	guard.managed = true
	uid, gid, err := ManagedStoreOwner(dataDir)
	if err != nil {
		guard.Close()
		return nil, fmt.Errorf("resolve managed signer service principal: %w", err)
	}
	guard.uid, guard.gid = uid, gid
	return guard, nil
}

func (g *OfflineMutation) Normalize() error {
	if g == nil || !g.managed {
		return nil
	}
	return NormalizeStore(g.dataDir, g.uid, g.gid)
}

func (g *OfflineMutation) Close() {
	if g != nil && g.lock != nil {
		_ = g.lock.Close()
		g.lock = nil
	}
}
