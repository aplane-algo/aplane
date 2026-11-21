// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/sourcetokens"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// A cosigner key's source tokens travel with the key, as its own policy
// does: a backup carries source_tokens/<selector>.apb beside the key's
// credential, holding the token file's canonical plaintext encrypted under
// the export passphrase, and restore writes it as the key's token file
// under the destination term. The node default's tokens are not backed up,
// as the node default policy is not. No function here puts a token in an
// error, and every decrypted copy is zeroed.

// backupSourceTokensDir is the archive directory of per-key source tokens.
const backupSourceTokensDir = "source_tokens"

// maxBackupSourceTokensEnvelopeBytes bounds one archived token envelope: a
// token file is at most 4 KiB encrypted, and its plaintext grows by base64
// and the standalone envelope's JSON.
const maxBackupSourceTokensEnvelopeBytes = 8 << 10

// backupSourceTokensDirFor returns the source tokens directory beside an
// extracted archive's credential directory.
func backupSourceTokensDirFor(keysDir string) string {
	return filepath.Join(filepath.Dir(keysDir), backupSourceTokensDir)
}

// exportKeySourceTokens writes the token file of each selected cosigner key
// that has one, re-encrypted under the export passphrase. It returns the
// keys whose tokens were exported. A token file that cannot be read fails
// the backup. Only a cosigner node holds token files.
func exportKeySourceTokens(active storepaths.GenPaths, role noderole.Role, stageDir string, selectors []string, kr *crypto.Keyring, exportPassphrase []byte) ([]string, error) {
	if role != noderole.RoleCosigner {
		return nil, nil
	}
	destDir := filepath.Join(stageDir, backupSourceTokensDir)
	var exported []string
	for _, selector := range selectors {
		// A key's selector is never "default", and an account key's address
		// is not a token selector.
		if selector == sourcetokens.DefaultSelector || sourcetokens.ValidateSelector(selector) != nil {
			continue
		}
		sealed, ok, err := sealKeySourceTokens(active, selector, kr, exportPassphrase)
		if err != nil {
			return nil, fmt.Errorf("export source tokens for %s: %w", selector, err)
		}
		if !ok {
			continue
		}
		if err := fsutil.MkdirAllPrivate(destDir); err != nil {
			return nil, fmt.Errorf("create backup source tokens directory: %w", err)
		}
		if err := os.WriteFile(filepath.Join(destDir, selector+".apb"), sealed, 0o600); err != nil {
			return nil, fmt.Errorf("write source tokens for %s: %w", selector, err)
		}
		exported = append(exported, selector)
	}
	return exported, nil
}

// sealKeySourceTokens reads selector's token file and encrypts its canonical
// plaintext under the export passphrase. ok is false when it has none.
func sealKeySourceTokens(active storepaths.GenPaths, selector string, kr *crypto.Keyring, exportPassphrase []byte) ([]byte, bool, error) {
	f, ok, err := sourcetokens.ReadFile(active, selector, kr)
	if err != nil || !ok {
		return nil, false, err
	}
	plaintext, err := sourcetokens.Encode(f)
	f.Zero()
	if err != nil {
		return nil, false, err
	}
	defer crypto.ZeroBytes(plaintext)
	sealed, err := crypto.EncryptStandalone(plaintext, exportPassphrase)
	if err != nil {
		return nil, false, fmt.Errorf("encrypt: %w", err)
	}
	// A token file is small enough that this cannot happen; the check keeps
	// a backup from holding a member extraction would refuse.
	if len(sealed) > maxBackupSourceTokensEnvelopeBytes {
		return nil, false, fmt.Errorf("encrypted source tokens take %d bytes, more than an archive allows (%d)",
			len(sealed), maxBackupSourceTokensEnvelopeBytes)
	}
	return sealed, true, nil
}

// readBackupSourceTokens reads and decrypts the archived source tokens of one
// key. It returns nil when the archive carries none. The caller admits and
// zeroes the plaintext.
func readBackupSourceTokens(keysDir, selector string, exportPassphrase []byte) ([]byte, error) {
	path := filepath.Join(backupSourceTokensDirFor(keysDir), selector+".apb")
	data, _, err := fsutil.ReadRegularFileLimited(path, maxBackupSourceTokensEnvelopeBytes)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read backup source tokens: %w", err)
	}
	plaintext, err := crypto.DecryptStandaloneLimited(data, exportPassphrase, maxBackupSourceTokensEnvelopeBytes)
	if err != nil {
		return nil, fmt.Errorf("decrypt backup source tokens: %w", err)
	}
	return plaintext, nil
}

// scanBackupSourceTokens lists the keys an extracted archive carries source
// tokens for. Each member is named for a cosigner key: never "default",
// whose tokens a backup does not carry, and never an account address.
func scanBackupSourceTokens(keysDir string) ([]string, error) {
	entries, err := os.ReadDir(backupSourceTokensDirFor(keysDir))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var keysWithTokens []string
	for _, entry := range entries {
		key, ok := strings.CutSuffix(entry.Name(), ".apb")
		if !ok || key == sourcetokens.DefaultSelector || sourcetokens.ValidateSelector(key) != nil {
			return nil, fmt.Errorf("backup source tokens contain unsupported entry %q", entry.Name())
		}
		keysWithTokens = append(keysWithTokens, key)
	}
	return keysWithTokens, nil
}

// admitSourceTokens admits a credential's archived source tokens: they
// belong to a cosigner key, decode as that key's token file, and fit one
// under any term. It keeps the plaintext and the source names in the entry,
// which then owns the plaintext. A nil plaintext admits nothing.
func (e *CredentialEntry) admitSourceTokens(plaintext []byte) error {
	if plaintext == nil {
		return nil
	}
	if e.Category() != keys.CategoryWitness {
		return fmt.Errorf("backup source tokens for %s: only a cosigner key has source tokens", e.Selector())
	}
	f, err := sourcetokens.DecodeSealable(plaintext, e.Selector())
	if err != nil {
		return fmt.Errorf("backup source tokens for %s: %w", e.Selector(), err)
	}
	defer f.Zero()
	names := make([]string, 0, len(f.Tokens))
	for _, entry := range f.Listing() {
		names = append(names, entry.Source)
	}
	e.credential.sourceTokens = plaintext
	e.credential.sourceTokenNames = names
	return nil
}

// classifyRestoreSourceTokens decides whether an entry's archived source
// tokens are installed, as classifyRestorePolicy does for its policy: a
// destination without a token file takes the archived one; an identical one
// is kept; a different or unreadable one is a conflict that
// replace_existing resolves. The destination's tokens are kept when the
// archive carries none. A conflict names the encrypted file's digest,
// never a digest of the tokens.
func classifyRestoreSourceTokens(active storepaths.GenPaths, entry CredentialEntry, kr *crypto.Keyring, result *RestoreClassification) {
	archived := entry.sourceTokensPlaintext()
	if archived == nil {
		return
	}
	conflict := RestoreConflict{Selector: entry.Selector(), Category: entry.Category(), KeyType: entry.KeyType()}
	current, held, err := sourcetokens.ReadFile(active, entry.Selector(), kr)
	switch {
	case err != nil:
		conflict.ExistingSHA256 = fileSHA256BestEffort(active.SourceTokenPath(entry.Selector()))
		conflict.Reason = "existing source tokens are unreadable: " + err.Error()
		result.Conflicts = append(result.Conflicts, conflict)
	case !held:
	default:
		same, compareErr := sameSourceTokens(current, archived)
		current.Zero()
		if compareErr == nil && same {
			return
		}
		conflict.ExistingSHA256 = fileSHA256BestEffort(active.SourceTokenPath(entry.Selector()))
		conflict.Reason = "existing source tokens differ from backup"
		result.Conflicts = append(result.Conflicts, conflict)
	}
	result.SourceTokens = append(result.SourceTokens, entry)
}

// sameSourceTokens reports whether current encodes to exactly archived.
func sameSourceTokens(current *sourcetokens.File, archived []byte) (bool, error) {
	canonical, err := sourcetokens.Encode(current)
	if err != nil {
		return false, err
	}
	defer crypto.ZeroBytes(canonical)
	return bytes.Equal(canonical, archived), nil
}

// ApplySourceTokensEntry writes a restored credential's archived source
// tokens as its token file, sealed under the destination keyring's current
// term with the source-tokens object context.
func ApplySourceTokensEntry(active storepaths.GenPaths, entry CredentialEntry, kr *crypto.Keyring) error {
	archived := entry.sourceTokensPlaintext()
	if archived == nil {
		return fmt.Errorf("restore entry %s carries no source tokens", entry.Selector())
	}
	f, err := sourcetokens.DecodeSealable(archived, entry.Selector())
	if err != nil {
		return err
	}
	defer f.Zero()
	return sourcetokens.WriteFile(active, f, kr)
}
