package productruntime

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// These tests anchor KU2 in docs/FORMAL_TRACEABILITY.md: the register guard
// (RegisterChecksLock in key_use_lock.tla) and the drain (DrainWaits).

const keyUseTestTimeout = 5 * time.Second

func requireCancelled(t *testing.T, ctx context.Context, what string) {
	t.Helper()
	select {
	case <-ctx.Done():
	default:
		t.Fatalf("%s: context is live, want it already cancelled", what)
	}
}

func requireLive(t *testing.T, ctx context.Context, what string) {
	t.Helper()
	if err := ctx.Err(); err != nil {
		t.Fatalf("%s: context is cancelled (%v), want it live", what, err)
	}
}

// lockAsync runs Lock in the background and returns a channel closed when it
// returns.
func lockAsync(ir *Runtime) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		ir.Lock()
		close(done)
	}()
	return done
}

func waitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(keyUseTestTimeout):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func TestKeyUseContextRefusesWhileLocked(t *testing.T) {
	ir := New(Config{})

	// New starts locked.
	ctx, release := ir.KeyUseContext(context.Background())
	requireCancelled(t, ctx, "key use registered before the first unlock")
	release()

	ir.SetUnlocked()
	ir.Lock()

	ctx, release = ir.KeyUseContext(context.Background())
	requireCancelled(t, ctx, "key use registered after a lock")
	release()
	release() // A refused registration's release is a no-op, however often it runs.

	lockCtx, cancel := ir.LockCancelContext(context.Background())
	requireCancelled(t, lockCtx, "lock-cancel context taken after a lock")
	cancel()

	// A refused registration must not have joined the drain: the next lock
	// would otherwise wait for a release that never comes.
	ir.SetUnlocked()
	waitClosed(t, lockAsync(ir), "a lock after refused registrations")
}

func TestLockWaitsForAKeyUseAndRefusesNewOnesWhileDraining(t *testing.T) {
	ir := New(Config{})
	ir.SetUnlocked()

	holderCtx, holderRelease := ir.KeyUseContext(context.Background())
	requireLive(t, holderCtx, "key use registered while unlocked")
	revBefore := ir.KeysetRevision()

	lockDone := lockAsync(ir)

	// The drain cancels the holder's context only after the state is locked.
	waitClosed(t, holderCtx.Done(), "the lock to cancel the registered key use")
	if ir.IsUnlocked() {
		t.Fatal("holder was cancelled while the state still reads unlocked")
	}

	// Registering during the drain is refused, so the drain never has to
	// wait for a holder that arrived after it began.
	lateCtx, lateRelease := ir.KeyUseContext(context.Background())
	requireCancelled(t, lateCtx, "key use registered during the drain")
	lateRelease()

	// The session is not cleared while the holder is registered.
	select {
	case <-lockDone:
		t.Fatal("Lock returned while a key use was still registered")
	case <-time.After(50 * time.Millisecond):
	}
	if got := ir.KeysetRevision(); got != revBefore {
		t.Fatalf("session cleared under a registered key use: KeysetRevision %d -> %d", revBefore, got)
	}

	holderRelease()
	waitClosed(t, lockDone, "Lock to return after the key use released")
	if got := ir.KeysetRevision(); got != revBefore+1 {
		t.Fatalf("KeysetRevision after lock = %d, want %d", got, revBefore+1)
	}
	holderRelease() // Release is idempotent; a second call must not underflow the drain.
}

func TestKeyUseAfterAnotherUnlockIsLiveAndEndsAtTheNextLock(t *testing.T) {
	ir := New(Config{})
	ir.SetUnlocked()
	ir.Lock()

	ir.SetUnlocked()
	ctx, release := ir.KeyUseContext(context.Background())
	requireLive(t, ctx, "key use registered after the signer unlocked again")
	lockCtx, cancel := ir.LockCancelContext(context.Background())
	defer cancel()
	requireLive(t, lockCtx, "lock-cancel context taken after the signer unlocked again")

	lockDone := lockAsync(ir)
	waitClosed(t, ctx.Done(), "the second lock to cancel the key use")
	waitClosed(t, lockCtx.Done(), "the second lock to cancel the lock-cancel context")
	release()
	waitClosed(t, lockDone, "the second lock to return")
}

// TestKeyUseRacingLockIsDrainedOrRefused races registrations against lock
// transitions. Every registration must either come back refused or be one the
// lock waits for: when Lock returns, no holder that got a live context may
// still be holding.
func TestKeyUseRacingLockIsDrainedOrRefused(t *testing.T) {
	ir := New(Config{})
	const (
		rounds  = 50
		holders = 8
	)
	for round := 0; round < rounds; round++ {
		ir.SetUnlocked()

		// roundCtx only unblocks holders if a broken guard leaves one waiting
		// on a context no lock will cancel.
		roundCtx, endRound := context.WithCancel(context.Background())
		var holding atomic.Int64
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < holders; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				for roundCtx.Err() == nil {
					ctx, release := ir.KeyUseContext(roundCtx)
					if ctx.Err() != nil {
						release()
						return
					}
					holding.Add(1)
					<-ctx.Done()
					holding.Add(-1)
					release()
				}
			}()
		}

		close(start)
		lockDone := lockAsync(ir)
		select {
		case <-lockDone:
		case <-time.After(keyUseTestTimeout):
			endRound()
			t.Fatalf("round %d: Lock did not return; a key use registered after it began", round)
		}
		n := holding.Load()
		endRound()
		wg.Wait()
		if n != 0 {
			t.Fatalf("round %d: Lock returned with %d key uses still holding", round, n)
		}
	}
}

// Destroy refuses every key use from the moment it begins, as a lock does,
// though it does not lock the signer. Key uses racing it are either drained
// or refused, so it returns with none holding, and one requested after it is
// refused too. Shutdown once left KeyUseContext handing out fresh live
// contexts while it drained, adding to the wait group it was waiting on.
func TestDestroyRefusesKeyUsesDuringAndAfterIt(t *testing.T) {
	const (
		rounds  = 20
		holders = 8
	)
	for round := 0; round < rounds; round++ {
		root := t.TempDir()
		ir := New(Config{
			KeyStore: keystore.NewAtomicFileKeyStoreForPaths(storepaths.NewPaths(root)),
			KeyPaths: storepaths.NewPaths(root),
		})
		ir.SetUnlocked()
		ir.SnapshotKeySession().InitializeSession()

		// roundCtx only unblocks holders if a broken guard leaves one waiting
		// on a context nothing will cancel.
		roundCtx, endRound := context.WithCancel(context.Background())
		var holding atomic.Int64
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < holders; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				for roundCtx.Err() == nil {
					ctx, release := ir.KeyUseContext(roundCtx)
					if ctx.Err() != nil {
						release()
						return
					}
					holding.Add(1)
					<-ctx.Done()
					holding.Add(-1)
					release()
				}
			}()
		}

		close(start)
		destroyCtx, endDestroy := context.WithTimeout(context.Background(), keyUseTestTimeout)
		err := ir.EndKeyUses(destroyCtx)
		endDestroy()
		ir.Destroy()
		n := holding.Load()
		endRound()
		wg.Wait()
		if err != nil || n != 0 {
			t.Fatalf("round %d: Destroy = %v with %d key uses still holding; want every racing key use drained or refused", round, err, n)
		}

		ctx, release := ir.KeyUseContext(context.Background())
		requireCancelled(t, ctx, "key use requested after Destroy")
		release()
		lockCtx, cancel := ir.LockCancelContext(context.Background())
		requireCancelled(t, lockCtx, "lock-cancel context taken after Destroy")
		cancel()
		if _, err := ir.SnapshotKeySession().GetKey("missing"); !errors.Is(err, keystore.ErrStoreLocked) {
			t.Fatalf("round %d: key session after Destroy = %v, want ErrStoreLocked", round, err)
		}
	}
}

// A key use requested while Destroy waits for one already registered is
// refused at once, and Destroy still waits for the registered one.
func TestDestroyRefusesAKeyUseWhileItDrains(t *testing.T) {
	ir := New(Config{})
	ir.SetUnlocked()
	held, releaseHeld := ir.KeyUseContext(context.Background())
	requireLive(t, held, "key use registered before shutdown")

	destroyed := make(chan error, 1)
	go func() { destroyed <- ir.EndKeyUses(context.Background()) }()
	waitClosed(t, held.Done(), "Destroy to cancel the registered key use")

	ctx, release := ir.KeyUseContext(context.Background())
	requireCancelled(t, ctx, "key use requested while Destroy drains")
	release()
	select {
	case err := <-destroyed:
		t.Fatalf("Destroy returned %v before the registered key use released", err)
	default:
	}
	releaseHeld()
	select {
	case err := <-destroyed:
		if err != nil {
			t.Fatalf("Destroy = %v after every key use released", err)
		}
	case <-time.After(keyUseTestTimeout):
		t.Fatal("Destroy did not return after the registered key use released")
	}
}
