// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientstate

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
)

// CacheChanges records APCLIENT_DATA cache files that changed since the last drain.
type CacheChanges struct {
	Alias  bool
	Set    bool
	Signer bool
	ASA    map[string]bool
	Auth   map[string]bool
}

func (c CacheChanges) Empty() bool {
	return !c.Alias && !c.Set && !c.Signer && len(c.ASA) == 0 && len(c.Auth) == 0
}

func (c *CacheChanges) markFile(name string) bool {
	switch name {
	case "alias_cache.json":
		c.Alias = true
		return true
	case "set_cache.json":
		c.Set = true
		return true
	case "signer_cache.json":
		c.Signer = true
		return true
	}

	if network, ok := strings.CutSuffix(name, "_asa_cache.json"); ok && network != "" {
		if c.ASA == nil {
			c.ASA = make(map[string]bool)
		}
		c.ASA[network] = true
		return true
	}
	if network, ok := strings.CutSuffix(name, "_auth_cache.json"); ok && network != "" {
		if c.Auth == nil {
			c.Auth = make(map[string]bool)
		}
		c.Auth[network] = true
		return true
	}
	return false
}

// CacheWatcher passively tracks signed cache-file changes under APCLIENT_DATA.
// It only marks dirty files; callers decide when to reload in-memory state.
type CacheWatcher struct {
	watcher *fsnotify.Watcher
	done    chan struct{}
	once    sync.Once

	mu      sync.Mutex
	changes CacheChanges
}

func StartCacheWatcher(dataDir string) (*CacheWatcher, error) {
	if dataDir == "" {
		return nil, nil
	}
	cacheDir := filepath.Join(dataDir, "cache")
	if err := os.MkdirAll(cacheDir, 0o770); err != nil {
		return nil, err
	}

	fswatcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	if err := fswatcher.Add(cacheDir); err != nil {
		_ = fswatcher.Close()
		return nil, err
	}

	w := &CacheWatcher{
		watcher: fswatcher,
		done:    make(chan struct{}),
	}
	go w.run()
	return w, nil
}

func (w *CacheWatcher) run() {
	for {
		select {
		case event, ok := <-w.watcher.Events:
			if !ok {
				return
			}
			if event.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Remove|fsnotify.Rename) != 0 {
				w.MarkFile(filepath.Base(event.Name))
			}
		case _, ok := <-w.watcher.Errors:
			if !ok {
				return
			}
		case <-w.done:
			return
		}
	}
}

func (w *CacheWatcher) MarkFile(name string) bool {
	if w == nil {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.changes.markFile(name)
}

func (w *CacheWatcher) Drain() CacheChanges {
	if w == nil {
		return CacheChanges{}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	changes := w.changes
	w.changes = CacheChanges{}
	return changes
}

func (w *CacheWatcher) Close() error {
	if w == nil {
		return nil
	}
	var err error
	w.once.Do(func() {
		close(w.done)
		err = w.watcher.Close()
	})
	return err
}
