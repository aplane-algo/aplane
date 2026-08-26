// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package genstore

import (
	"fmt"
	"os"

	"github.com/aplane-algo/aplane/internal/storepaths"
)

// Resolve returns the authenticated generation capability already bound to
// paths. Authentication of store-root.enc belongs at the runtime boundary;
// lower-level consumers may pass the resulting capability but cannot resolve
// selection from unauthenticated public state.
func Resolve(paths storepaths.Paths) (storepaths.GenPaths, error) {
	generationID, ok := paths.BoundActiveGeneration()
	if !ok {
		return storepaths.GenPaths{}, fmt.Errorf(
			"active generation capability is not bound; authenticate store-root.enc first",
		)
	}
	return paths.GenerationPaths(generationID), nil
}

func requireRegularDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("not a regular directory: %s", path)
	}
	return nil
}

// ResolveActive is Resolve projected through the narrow ActivePaths surface.
func ResolveActive(paths storepaths.Paths) (storepaths.ActivePaths, error) {
	return Resolve(paths)
}
