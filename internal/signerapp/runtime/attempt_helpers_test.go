// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package runtime

// tryUnlock runs an unlock attempt as the product runtime drives one: the
// reading (BeginAttempt), the work between it and the fence (unlockFn, a
// load), the publish, and onUnlocked once published. It returns unlockFn's
// key count, or the error that ended the attempt.
func tryUnlock(r *Runtime, unlockFn func() (int, error), onUnlocked func()) (int, error) {
	attempt := r.BeginAttempt()
	keyCount, err := unlockFn()
	if err != nil {
		return 0, err
	}
	if err := r.PublishUnlocked(attempt); err != nil {
		return 0, err
	}
	if onUnlocked != nil {
		onUnlocked()
	}
	return keyCount, nil
}

// tryRecovery runs an attempt that ends by entering recovery, with open
// opening the keyring recovery needs.
func tryRecovery(r *Runtime, open func() error) error {
	return r.EnterRecovery(r.BeginAttempt(), open)
}
