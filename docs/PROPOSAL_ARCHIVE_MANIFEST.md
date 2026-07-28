# Proposal: Authenticated Backup Archive Manifest

**Status:** accepted and implemented. Retained as the rationale record for the archive trust model; the normative contract lives in ARCH_CONTRACTS.md.
**Scope:** backup archive format, recovered-review source-context machinery,
and the admin protocol v3 source-context fields.
**Decides:** the "simplify or authenticate source context" question from the
external design review.

## 1. Problem

Two problems share one root: nothing authenticates a backup archive as a
whole.

**Integrity gap.** Each `.apb` payload is individually authenticated
(AES-256-GCM under an Argon2id key derived from the export passphrase), but
the archive around the payloads is not. `manifest.json` and
`source_settings.json` are unauthenticated plaintext, and the member list
itself is unauthenticated. An attacker who can modify an archive in transit
or at rest — without knowing the export passphrase — can:

- remove members undetected (a missing `.apb` is invisible; each payload
  authenticates only itself),
- alter or strip the source node role and source settings (only
  display/default consequences, but silently),
- replace the policy snapshot the operator inspects (its `.hmac` sidecar is
  bound to the *source* store's key, which the destination cannot verify).

**Complexity.** Because source context is unauthenticated by design, the
system carries machinery to say so precisely: an independent schema
(`aplane.backup.source-settings.v1`) with canonical mapping rules and
size/count limits, a `missing | unverified | invalid` tri-state, the
protocol-v3 constant compatibility entries in `unknown_source_settings`, the
protocol 3.1 typed-context fields with precedence rules over those entries,
the protocol 3.2 acknowledgement field with old-server fallback, and the
CLI/TUI rendering rules that keep "unverified" from reading as a verdict.
That is roughly 550 lines in `internal/backup` plus protocol constants,
review projection, and two rendering surfaces — for metadata that never
affects destination behavior.

## 2. Options

### Option A — simplify to labeled diagnostics

Keep the format; delete the trust-state machinery. Source context renders as
plainly labeled unauthenticated text ("reported by the archive, not
verified"), the tri-state and the compatibility entries disappear from the
protocol, and no new crypto is introduced.

- Cheap: mostly deletion.
- Leaves the integrity gap untouched: member removal, role/settings
  tampering, and policy-snapshot replacement remain undetectable.

### Option B — authenticated archive manifest (recommended)

New archive envelope generation where one manifest covers everything, and
the manifest itself is protected under the export passphrase.

**Manifest content** (single record, replacing today's `manifest.json` and
`source_settings.json`):

- schema + creation metadata,
- source node role,
- the complete member inventory: `{path, sha256, size}` for every archive
  member — `apb/*.apb`, `policy/*`, `README.md` — no exceptions,
- the source-context settings embedded inline (the separate file, its
  separate schema, and its standalone size limits disappear; the manifest's
  own size cap bounds them).

**Protection:** the manifest is sealed with the same standalone encryption
envelope the `.apb` payloads already use (Argon2id + AES-256-GCM under the
export passphrase, own salt/nonce). Reusing the existing envelope avoids new
cryptographic constructions; GCM provides the authentication. Domain
separation comes from the manifest's distinct schema identifier inside the
sealed plaintext.

**Verification:** any operation that opens the archive with the export
passphrase (preview, recover, import, rebuild, deep verify) decrypts the
manifest first and verifies every member against the inventory. Outcomes
collapse to two:

- manifest decrypts and every member matches → the archive is authentic as
  a whole; source context is *authenticated* (endorsed by whoever held the
  export passphrase at creation),
- anything else → the archive is rejected with the existing
  `invalid_backup_archive` class, indistinguishable from payload tampering
  today.

**Trust semantics preserved.** Authentication proves provenance and
integrity, not safety. Source settings remain review context only: they
never change policy verdicts, signing behavior, network resolution, or
acknowledgement requirements, and the policy snapshot is still never
installed. The only change is that what the review screen shows is
tamper-evident instead of spoofable.

**What it deletes:**

- the `missing | unverified | invalid` tri-state and its inspection code
  (`source_settings.go`, most of the status plumbing in
  `backupadmin/review.go`),
- `unknown_source_settings` and the `RecoverySourceSetting*` constant
  compatibility entries,
- the protocol 3.0/3.1/3.2 source-context layering and old-peer fallback
  rules — collapsed into one v3 shape with typed fields only (protocol v3
  has never shipped, so this is free exactly once),
- the "Source metadata unavailable" rendering branches and their
  precedence rules,
- the standalone `aplane.backup.source-settings.v1` schema and its limits.

`unattended_signing_ack_required` stays: it is destination-derived and
orthogonal to source trust. The TEAL recompilation gate in `backup import`
is likewise orthogonal (template provenance, not archive integrity) and is
untouched by this proposal.

### Trust model: passphrase knowledge is authentication

This proposal takes the explicit position that knowledge of the export
passphrase is sufficient authentication for archive content. A valid
archive proves exactly one thing: it was created, or endorsed, by a party
that knew the export passphrase. This is not a new assumption — it is the
trust root the `.apb` payloads have always had (a passphrase holder could
always fabricate a complete counterfeit archive, keys included), extended
to cover the archive's shape. The manifest reduces the
attacker-without-the-passphrase to zero capability and leaves the
attacker-with-the-passphrase exactly as powerful as today.

Consequences, stated so nothing more is read into it later:

- this is shared-secret authentication, not origin authentication: any
  legitimate passphrase recipient (the restoring operator) can mint
  archives indistinguishable from the source's. In the single-operator
  model, source and destination are one trust domain, so the distinction
  is vacuous; cross-party archive exchange would require revisiting this
  position,
- authentication strength equals passphrase secrecy and entropy; Argon2id
  slows brute force, but a weak passphrase yields forging ability along
  with the read ability it already yields,
- authenticated is not safe: source settings remain review context only
  and the policy snapshot is never installed,
- no trust qualifier survives in the product: an archive is either
  authentic or rejected, and the review screen's "reported by the
  archive" label describes scope (source facts, not destination facts),
  not trust. Stronger origin authentication (per-store signing keys) is
  rejected: it would require a public-key trust anchor between identities
  that does not exist in the product model, break the archive's
  standalone manually-decryptable property, and defend a boundary the
  passphrase holder has already crossed.

## 3. Costs

- **New archive generation; old archives unreadable.** Acceptable now:
  there are no operators, archives are regenerable from live stores, and
  the release policy already makes every release's store format
  self-contained. The existing `unsupported_backup_format` rejection covers
  old archives with actionable text.
- **Export cost:** hashing every member at creation — negligible against
  the encryption already done.
- **Review surface:** one new sealed record and its verification path need
  the same scrutiny as the `.apb` envelope; reuse keeps that small.

## 4. Resolved questions

Decided under a maximal-simplification directive:

1. **`apstore verify` requires the passphrase, always.** A passphrase-free
   structural mode cannot check the inventory, so its "pass" would be a
   weaker claim wearing the same name — the ambiguous-trust-state pattern
   this proposal exists to eliminate. One verify path, full verification.
   An archive is useless without its passphrase; the operator has it.
2. **No plaintext stub.** The sealed manifest's standalone envelope carries
   `envelope_version` in its cleartext header; that is the only version
   signal, and it is sufficient for a precise unsupported-format error. No
   separate stub file, no stub schema.
3. **Rebuild role default moves after the passphrase prompt.** The role
   comes from the sealed manifest once it is decrypted; `--role` remains
   the explicit override. No role is stored outside the manifest.
4. **Manifest authentication failure folds into the existing
   decrypt-failure and rate-limit class.** It is indistinguishable from a
   wrong passphrase (GCM), exactly as payload tampering already is. No new
   failure taxonomy.
5. **`source_settings_status` is dropped entirely.** Every v3 archive
   carries a manifest, so typed fields are present when the source recorded
   them and rendered "not recorded" otherwise. No status enum survives.

## 5. Sequencing

1. Decide the open questions above.
2. One change, hard cut (no compatibility path): archive writer + reader on
   the sealed manifest; delete the superseded machinery in the same change
   so the tri-state never coexists with the manifest.
3. Collapse the protocol fields and the CLI/TUI rendering.
4. Docs sweep: ARCH_CONTRACTS backup contract, archive README template,
   ARCH_ADMIN_PROTOCOL review fields, user guides.

Land before protocol v3 ships; independent of the keyterm rotation
proposal, but smaller — do this first.
