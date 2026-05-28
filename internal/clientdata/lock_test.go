// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientdata

import (
	"sync"
	"testing"
	"time"
)

func TestWithExclusiveLockSerializesSameDataDir(t *testing.T) {
	dataDir := t.TempDir()

	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondFinished := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if err := WithExclusiveLock(dataDir, func() error {
			close(firstEntered)
			<-releaseFirst
			return nil
		}); err != nil {
			t.Errorf("first WithExclusiveLock() error = %v", err)
		}
	}()

	select {
	case <-firstEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("first lock holder did not enter")
	}

	go func() {
		defer wg.Done()
		if err := WithExclusiveLock(dataDir, func() error {
			close(secondFinished)
			return nil
		}); err != nil {
			t.Errorf("second WithExclusiveLock() error = %v", err)
		}
	}()

	select {
	case <-secondFinished:
		t.Fatal("second lock holder entered before first released lock")
	case <-time.After(100 * time.Millisecond):
	}

	close(releaseFirst)

	select {
	case <-secondFinished:
	case <-time.After(2 * time.Second):
		t.Fatal("second lock holder did not enter after first released lock")
	}

	wg.Wait()
}

func TestWithExclusiveLockAllowsIndependentDirs(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()

	enteredA := make(chan struct{})
	enteredB := make(chan struct{})
	release := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if err := WithExclusiveLock(dirA, func() error {
			close(enteredA)
			<-release
			return nil
		}); err != nil {
			t.Errorf("WithExclusiveLock(dirA) error = %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		if err := WithExclusiveLock(dirB, func() error {
			close(enteredB)
			<-release
			return nil
		}); err != nil {
			t.Errorf("WithExclusiveLock(dirB) error = %v", err)
		}
	}()

	select {
	case <-enteredA:
	case <-time.After(2 * time.Second):
		t.Fatal("dirA lock holder did not enter")
	}

	select {
	case <-enteredB:
	case <-time.After(2 * time.Second):
		t.Fatal("dirB lock holder did not enter")
	}

	close(release)
	wg.Wait()
}
