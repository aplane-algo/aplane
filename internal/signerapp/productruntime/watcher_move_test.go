// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package productruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	apkeys "github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// startedWatcher is one watcher a watcherRecorder started.
type startedWatcher struct {
	dirs []string
	ctx  context.Context
}

// watcherRecorder is a WatcherStartFunc that watches nothing and records what
// it was asked to. onStart, if set, runs inside each start and may fail it.
type watcherRecorder struct {
	mu      sync.Mutex
	started []startedWatcher
	onStart func() error
}

func (r *watcherRecorder) start(dirs []string, ctx context.Context, _ func() error) error {
	r.mu.Lock()
	onStart := r.onStart
	r.mu.Unlock()
	if onStart != nil {
		if err := onStart(); err != nil {
			return err
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.started = append(r.started, startedWatcher{slices.Clone(dirs), ctx})
	return nil
}

func (r *watcherRecorder) setOnStart(fn func() error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onStart = fn
}

// requireWatching checks that want were watched in turn, that only the last
// watcher still runs, and that it does.
func (r *watcherRecorder) requireWatching(t *testing.T, want ...[]string) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	var got [][]string
	for i, watcher := range r.started {
		got = append(got, watcher.dirs)
		if running := watcher.ctx.Err() == nil; running != (i == len(r.started)-1) {
			t.Errorf("watcher %d of %d running = %v", i+1, len(r.started), running)
		}
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("watched\n%q\nwant\n%q", got, want)
	}
}

// watchedDirs is what a watcher of gen watches, and of only the store root
// when gen is nil.
func watchedDirs(ir *Runtime, gen *storepaths.GenPaths) []string {
	dirs := []string{ir.KeyPaths().ProductDir()}
	if gen != nil {
		dirs = append(dirs, gen.KeysDir(), gen.KeyTypeRecordsDir())
	}
	return dirs
}

// buildSelecting makes the runtime's reloads find the store root selecting
// gen, nil for a root that does not authenticate, and fail with err if set.
func buildSelecting(ir *Runtime, gen *storepaths.GenPaths, err error) {
	ir.SetBuildFunc(func(*crypto.Keyring) (*Loaded, error) {
		loaded := &Loaded{Selection: gen}
		loaded.Contents.Selection = gen
		return loaded, err
	}, ReloadEffects{})
}

func requireReturns(t *testing.T, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not return", what)
	}
}

// The watcher follows the generation in service: a reload that ends bound to
// another generation moves it there, whether the reload published it or
// entered recovery on it, and one that ends bound to the same generation or to
// none leaves it as it is. The reload moves it under the store mutation lock,
// and on a store marked dirty, without waiting for that lock.
func TestAReloadMovesTheWatcherToTheGenerationInService(t *testing.T) {
	transient := errors.New("injected read failure")
	defect := fmt.Errorf("%w: 1 malformed key file(s)", signertemplates.ErrGenerationValidation)
	for _, tc := range []struct {
		name    string
		outcome genstore.MintOutcome
		moved   bool // the build finds the root selecting another generation
		noRoot  bool // the root does not authenticate
		err     error
		moves   bool
		state   string
	}{
		{name: "a commit", outcome: genstore.Committed, moved: true, moves: true, state: "unlocked"},
		{name: "a commit in doubt", outcome: genstore.Uncertain, moved: true, moves: true, state: "recovery"},
		{name: "a commit in doubt that did not land", outcome: genstore.Uncertain, state: "recovery"},
		{name: "a commit whose build fails", outcome: genstore.Committed, moved: true, err: transient, moves: true, state: "recovery"},
		{name: "a root that does not authenticate", outcome: genstore.Committed, noRoot: true, err: transient, state: "recovery"},
		{name: "a defect in the generation in service", outcome: genstore.Committed, err: defect, state: "recovery"},
		{name: "a failure that keeps the view in service", outcome: genstore.Committed, err: transient, state: "unlocked"},
		{name: "the same generation", outcome: genstore.Committed, state: "unlocked"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ir, bound, _ := viewInService(t)
			var mutation sync.Mutex
			ir.SetReloadMutationLock(func() sync.Locker { return &mutation })
			var watchers watcherRecorder
			ir.EnsureKeyWatcher(watchers.start)
			t.Cleanup(ir.StopKeyWatcher)
			ir.MarkDirty()

			next := ir.KeyPaths().GenerationPaths("gen-1800000000-0a0b0c0d")
			switch {
			case tc.noRoot:
				buildSelecting(ir, nil, tc.err)
			case tc.moved:
				buildSelecting(ir, &next, tc.err)
			default:
				buildSelecting(ir, &bound, tc.err)
			}
			mutation.Lock()
			requireReturns(t, "a reload on a dirty store under the store mutation lock", func() {
				_, _ = ir.FollowCommit(tc.outcome)
			})
			mutation.Unlock()

			if got := ir.GetState().String(); got != tc.state {
				t.Fatalf("state = %s, want %s", got, tc.state)
			}
			want := [][]string{watchedDirs(ir, &bound)}
			if tc.moves {
				want = append(want, watchedDirs(ir, &next))
			}
			watchers.requireWatching(t, want...)
			ir.watcherMu.Lock()
			dirty := ir.dirty
			ir.watcherMu.Unlock()
			if !dirty {
				t.Fatal("the move took the dirty mark an unlock reconciles")
			}
		})
	}
}

// A reconcile renews the watcher on the generation it leaves in service, whose
// directories may have been replaced, whether it succeeds, enters recovery or,
// when it is not explicit, only fails. The one it replaces ends.
func TestAReconcileRenewsTheWatcher(t *testing.T) {
	failure := errors.New("injected reconcile failure")
	for name, tc := range map[string]struct {
		explicit bool
		err      error
	}{
		"a success":                     {explicit: true},
		"a failure":                     {explicit: true, err: failure},
		"a rescan out of recovery":      {},
		"a failed rescan from recovery": {err: failure},
	} {
		t.Run(name, func(t *testing.T) {
			ir, bound, _ := viewInService(t)
			var watchers watcherRecorder
			ir.EnsureKeyWatcher(watchers.start)
			t.Cleanup(ir.StopKeyWatcher)
			if !tc.explicit {
				ir.EnterRecovery(nil)
			}
			watchers.requireWatching(t, watchedDirs(ir, &bound))

			if _, err := ir.Reconcile(func(*crypto.Keyring) error { return tc.err }, tc.explicit); !errors.Is(err, tc.err) {
				t.Fatalf("Reconcile() = %v, want %v", err, tc.err)
			}
			if recovery := tc.err != nil; ir.IsRecovery() != recovery {
				t.Fatalf("state = %v", ir.GetState())
			}
			// The rescan that fails reloads nothing; the service's call renews.
			ir.EnsureKeyWatcher(watchers.start)
			watchers.requireWatching(t, watchedDirs(ir, &bound), watchedDirs(ir, &bound))
			ir.EnsureKeyWatcher(watchers.start)
			watchers.requireWatching(t, watchedDirs(ir, &bound), watchedDirs(ir, &bound))
		})
	}
}

// A lock leaves the watcher on its generation, and the unlock that follows
// moves it to the one the store root then selects.
func TestAnUnlockMovesTheWatcher(t *testing.T) {
	ir, _, _, _ := unlockedRuntimeForTest(t)
	bound, err := ir.ActivePaths()
	if err != nil {
		t.Fatal(err)
	}
	var watchers watcherRecorder
	ir.EnsureKeyWatcher(watchers.start)
	t.Cleanup(ir.StopKeyWatcher)

	ir.Lock()
	if _, err := ir.Reload(); err == nil {
		t.Fatal("a locked signer reloaded")
	}
	ir.EnsureKeyWatcher(watchers.start)
	watchers.requireWatching(t, watchedDirs(ir, &bound))

	next := ir.KeyPaths().GenerationPaths("gen-1800000000-0a0b0c0d")
	buildSelecting(ir, &next, nil)
	onUnlocked := false
	if _, err := ir.Unlock([]byte(secondUnlockPassphrase), func(*crypto.Keyring) error { return nil }, func() {
		onUnlocked = true
		ir.EnsureKeyWatcher(watchers.start)
	}); err != nil || !onUnlocked || !ir.IsUnlocked() {
		t.Fatalf("Unlock() = %v, onUnlocked %v, state %v", err, onUnlocked, ir.GetState())
	}
	watchers.requireWatching(t, watchedDirs(ir, &bound), watchedDirs(ir, &next))
}

// An unlock that enters recovery moves a running watcher to what recovery is
// bound to.
func TestAnUnlockIntoRecoveryMovesTheWatcher(t *testing.T) {
	ir, _, _, _ := unlockedRuntimeForTest(t)
	bound, err := ir.ActivePaths()
	if err != nil {
		t.Fatal(err)
	}
	var watchers watcherRecorder
	ir.EnsureKeyWatcher(watchers.start)
	t.Cleanup(ir.StopKeyWatcher)
	ir.Lock()

	next := ir.KeyPaths().GenerationPaths("gen-1800000000-0a0b0c0d")
	buildSelecting(ir, &next, nil)
	outcome, err := ir.Unlock([]byte(secondUnlockPassphrase), func(*crypto.Keyring) error { return errors.New("injected reconcile failure") }, nil)
	if err != nil || !outcome.Recovery {
		t.Fatalf("Unlock() = %+v, %v; want recovery", outcome, err)
	}
	watchers.requireWatching(t, watchedDirs(ir, &bound), watchedDirs(ir, &next))
}

// A passphrase change's republish moves the watcher, whether or not a lock
// that raced it leaves the signer locked.
func TestAPassphraseChangeMovesTheWatcher(t *testing.T) {
	for _, republish := range []bool{true, false} {
		t.Run(fmt.Sprintf("republish %v", republish), func(t *testing.T) {
			ir, _, _, _ := unlockedRuntimeForTest(t)
			bound, err := ir.ActivePaths()
			if err != nil {
				t.Fatal(err)
			}
			var watchers watcherRecorder
			ir.EnsureKeyWatcher(watchers.start)
			t.Cleanup(ir.StopKeyWatcher)

			next := ir.KeyPaths().GenerationPaths("gen-1800000000-0a0b0c0d")
			buildSelecting(ir, &next, nil)
			token := ir.BeginStoreMaintenance()
			if _, err := ir.ReloadWithPassphrase([]byte(secondUnlockPassphrase)); err != nil {
				t.Fatal(err)
			}
			if published := ir.FinishStoreMaintenance(token, republish); published != republish {
				t.Fatalf("FinishStoreMaintenance() = %v", published)
			}
			watchers.requireWatching(t, watchedDirs(ir, &bound), watchedDirs(ir, &next))
		})
	}
}

// Changes seen while locked are reconciled once, and stay marked on a signer
// that is not unlocked.
func TestAStoreMarkedDirtyIsReconciledOnce(t *testing.T) {
	ir, _, loads, _ := unlockedRuntimeForTest(t)
	var watchers watcherRecorder
	t.Cleanup(ir.StopKeyWatcher)
	ir.Lock()
	ir.MarkDirty()
	ir.EnsureKeyWatcher(watchers.start)
	if n := loads.Load(); n != 0 {
		t.Fatalf("a locked signer loaded %d time(s)", n)
	}
	if _, err := ir.Unlock([]byte(secondUnlockPassphrase), func(*crypto.Keyring) error { return nil }, nil); err != nil {
		t.Fatal(err)
	}
	before := loads.Load()
	for range 2 {
		ir.EnsureKeyWatcher(watchers.start)
	}
	if n := loads.Load() - before; n != 1 {
		t.Fatalf("the mark was reconciled %d time(s), want 1", n)
	}
}

// A watcher started on a locked signer sees only the store root, until an
// unlock gives it a generation.
func TestAWatcherStartedLockedMovesAtTheUnlock(t *testing.T) {
	ir, _, _, _ := unlockedRuntimeForTest(t)
	ir.Lock()
	var watchers watcherRecorder
	ir.EnsureKeyWatcher(watchers.start)
	t.Cleanup(ir.StopKeyWatcher)
	ir.EnsureKeyWatcher(watchers.start)
	watchers.requireWatching(t, watchedDirs(ir, nil))

	if _, err := ir.Unlock([]byte(secondUnlockPassphrase), func(*crypto.Keyring) error { return nil }, nil); err != nil {
		t.Fatal(err)
	}
	bound, err := ir.ActivePaths()
	if err != nil {
		t.Fatal(err)
	}
	watchers.requireWatching(t, watchedDirs(ir, nil), watchedDirs(ir, &bound))
}

// A move that fails to start its watcher keeps the one running, which still
// sees the store root, and the next reload tries again. Without one running, a
// reload starts none.
func TestAFailedMoveKeepsTheRunningWatcher(t *testing.T) {
	ir, bound, _ := viewInService(t)
	next := ir.KeyPaths().GenerationPaths("gen-1800000000-0a0b0c0d")
	var watchers watcherRecorder
	ir.EnsureKeyWatcher(watchers.start)

	buildSelecting(ir, &next, nil)
	watchers.setOnStart(func() error { return errors.New("injected inotify failure") })
	if _, err := ir.FollowCommit(genstore.Committed); err != nil {
		t.Fatal(err)
	}
	watchers.requireWatching(t, watchedDirs(ir, &bound))

	watchers.setOnStart(nil)
	if _, err := ir.Reload(); err != nil {
		t.Fatal(err)
	}
	watchers.requireWatching(t, watchedDirs(ir, &bound), watchedDirs(ir, &next))

	ir.StopKeyWatcher()
	buildSelecting(ir, &bound, nil)
	if _, err := ir.FollowCommit(genstore.Committed); err != nil {
		t.Fatal(err)
	}
	if n := len(watchers.started); n != 2 {
		t.Fatalf("%d watchers started, want none after the stop", n-2)
	}

	// A stopped watcher starts again on whatever is then in service, though it
	// is the generation it watched before.
	ir.EnsureKeyWatcher(watchers.start)
	watchers.requireWatching(t, watchedDirs(ir, &bound), watchedDirs(ir, &next), watchedDirs(ir, &bound))
	ir.StopKeyWatcher()
	ir.EnsureKeyWatcher(watchers.start)
	watchers.requireWatching(t, watchedDirs(ir, &bound), watchedDirs(ir, &next), watchedDirs(ir, &bound), watchedDirs(ir, &bound))
	ir.StopKeyWatcher()
}

// A reload that changes the generation while a watcher is starting finds the
// start claimed. The start moves the watcher on once it is done, so the change
// is not missed, and only one watcher is left running.
func TestAGenerationChangedDuringAWatchersStartIsNotMissed(t *testing.T) {
	ir, bound, _ := viewInService(t)
	next := ir.KeyPaths().GenerationPaths("gen-1800000000-0a0b0c0d")
	var watchers watcherRecorder
	starting, resume := make(chan struct{}), make(chan struct{})
	watchers.setOnStart(func() error {
		watchers.setOnStart(nil)
		close(starting)
		<-resume
		return nil
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ir.EnsureKeyWatcher(watchers.start)
	}()
	t.Cleanup(ir.StopKeyWatcher)
	<-starting

	buildSelecting(ir, &next, nil)
	requireReturns(t, "a reload and a second start during the first", func() {
		if _, err := ir.FollowCommit(genstore.Committed); err != nil {
			t.Error(err)
		}
		ir.EnsureKeyWatcher(watchers.start)
	})
	close(resume)
	<-done
	watchers.requireWatching(t, watchedDirs(ir, &bound), watchedDirs(ir, &next))
}

// A start that read the generation in service before a commit changed it does
// not use what it read: it doesn't move back a watcher the commit moved, whether
// or not a lock lands next, and it moves one the commit left to it, having found
// the start claimed.
func TestAStartThatReadAnOldGenerationDoesNotUseIt(t *testing.T) {
	for name, tc := range map[string]struct{ moved, locked bool }{
		"the commit moved the watcher":                    {moved: true},
		"the commit moved the watcher, then a lock":       {moved: true, locked: true},
		"the commit left the watcher to the start's loop": {},
	} {
		t.Run(name, func(t *testing.T) {
			ir, bound, _ := viewInService(t)
			var watchers watcherRecorder
			ir.EnsureKeyWatcher(watchers.start)
			t.Cleanup(ir.StopKeyWatcher)

			// The start reads the generation and then waits for watcherMu,
			// while a commit installs the next one.
			next := ir.KeyPaths().GenerationPaths("gen-1800000000-0a0b0c0d")
			ir.watcherMu.Lock()
			ir.watcherGeneration = "gen-1700000000-0a0b0c0d"
			done := make(chan struct{})
			go func() {
				defer close(done)
				ir.armKeyWatcher(watchers.start)
			}()
			time.Sleep(100 * time.Millisecond)
			if err := ir.keyStore.WithKeyring(func(kr *crypto.Keyring) error {
				ir.keyStore.Install(kr, keystore.Contents{Selection: &next})
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if tc.moved {
				ir.watcherGeneration = next.GenerationID()
			}
			if tc.locked {
				ir.keyStore.ClearKeys()
			}
			ir.watcherMu.Unlock()
			<-done

			want := [][]string{watchedDirs(ir, &bound)}
			if !tc.moved {
				want = append(want, watchedDirs(ir, &next))
			}
			watchers.requireWatching(t, want...)
			ir.watcherMu.Lock()
			defer ir.watcherMu.Unlock()
			if ir.watcherGeneration != next.GenerationID() || ir.watcherStarting {
				t.Fatalf("the watcher is on %q, starting %v; want it on %s", ir.watcherGeneration, ir.watcherStarting, next.GenerationID())
			}
		})
	}
}

// A key read that stalls holds the keystore's cache lock, and a lock waiting
// behind it holds every other reader, a watcher's start among them. Shutdown's
// bounded step still returns at its deadline.
func TestAStalledKeyReadUnderAWatcherStartDoesNotHoldShutdown(t *testing.T) {
	ir, bound, _ := viewInService(t)
	address := types.Address{9}.String()
	fifo := filepath.Join(t.TempDir(), address+".key")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ir.keyStore.WithKeyring(func(kr *crypto.Keyring) error {
		ir.keyStore.Install(kr, keystore.Contents{Selection: &bound, Keys: map[string]apkeys.KeyScanInfo{address: {KeyFile: fifo, KeyType: "ed25519"}}})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var watchers watcherRecorder
	var wg sync.WaitGroup
	for _, step := range []func(){
		func() { _, _ = ir.keyStore.Get(context.Background(), address) },
		ir.keyStore.ClearKeys,
		func() { ir.armKeyWatcher(watchers.start) },
	} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			step()
		}()
		time.Sleep(100 * time.Millisecond)
	}
	requireReturns(t, "EndKeyUses behind a stalled key read", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		_ = ir.EndKeyUses(ctx)
	})

	// Read and write, so that this does not wait for a reader.
	release, err := os.OpenFile(fifo, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	_ = release.Close()
	wg.Wait()
	for i, watcher := range watchers.started {
		if watcher.ctx.Err() == nil {
			t.Errorf("watcher %d runs after shutdown", i+1)
		}
	}
}

// Concurrent starts and reloads leave one watcher running, on the generation
// in service.
func TestConcurrentWatcherStartsAndMovesLeaveOneWatcher(t *testing.T) {
	ir, _, _ := viewInService(t)
	var watchers watcherRecorder
	var mutation sync.Mutex
	var wg sync.WaitGroup
	var last storepaths.GenPaths
	for i := range 8 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			ir.EnsureKeyWatcher(watchers.start)
		}()
		go func() {
			defer wg.Done()
			mutation.Lock()
			defer mutation.Unlock()
			next := ir.KeyPaths().GenerationPaths(fmt.Sprintf("gen-180000000%d-0a0b0c0d", i))
			last = next
			buildSelecting(ir, &next, nil)
			_, _ = ir.FollowCommit(genstore.Committed)
		}()
	}
	wg.Wait()
	t.Cleanup(ir.StopKeyWatcher)
	running := 0
	for i, watcher := range watchers.started {
		if watcher.ctx.Err() == nil {
			running++
			if !slices.Equal(watcher.dirs, watchedDirs(ir, &last)) {
				t.Errorf("watcher %d still watches %q, want %q", i, watcher.dirs, watchedDirs(ir, &last))
			}
		}
	}
	if running != 1 {
		t.Fatalf("%d of %d watchers run, want 1", running, len(watchers.started))
	}
}

// Once shutdown begins no watcher starts: not one asked for or moved after it,
// and one already starting ends when its start returns.
func TestShutdownLeavesNoWatcher(t *testing.T) {
	ir, _, _ := viewInService(t)
	var watchers watcherRecorder
	starting, resume := make(chan struct{}), make(chan struct{})
	watchers.setOnStart(func() error {
		close(starting)
		<-resume
		return nil
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ir.EnsureKeyWatcher(watchers.start)
	}()
	<-starting
	if err := ir.EndKeyUses(context.Background()); err != nil {
		t.Fatal(err)
	}
	close(resume)
	<-done
	watchers.setOnStart(nil)

	ir.EnsureKeyWatcher(watchers.start)
	next := ir.KeyPaths().GenerationPaths("gen-1800000000-0a0b0c0d")
	buildSelecting(ir, &next, nil)
	if _, err := ir.FollowCommit(genstore.Committed); err != nil {
		t.Fatal(err)
	}
	if len(watchers.started) != 1 || watchers.started[0].ctx.Err() == nil {
		t.Fatalf("%d watchers started, the first running = %v; want the one in flight, ended",
			len(watchers.started), len(watchers.started) > 0 && watchers.started[0].ctx.Err() == nil)
	}
}
