# Setting Publish Machine-Checkable Model

> Status: TLC checked over the full finite state space; the recorded positive
> run generated 23 distinct reachable states at depth 5 with no
> counterexamples. Two expected-failure negative controls must keep
> producing their counterexamples: `setting_publish_negative_permissive.cfg`
> (`PermissiveAfterSave = FALSE`) violates `SP1_NeverMorePermissiveThanFile`
> after 5 distinct states at depth 2, and
> `setting_publish_negative_restrictive.cfg` (`RestrictiveFirst = FALSE`)
> violates `SP3_RestrictiveInEffectDuringSave` after 4 distinct states at
> depth 2.

A writable signer setting lives in two places: the value in effect, which a
signing request reads from memory, and the file, which the next start loads.
This model asks when a change takes effect relative to its save, for a
boolean setting with a restrictive value (`require_contained`,
`require_cosigner` and `lock_on_disconnect`: true; `user_auto_approve`:
false).

The spec lives at [formal/setting_publish.tla](formal/setting_publish.tla).

## What it covers

| Invariant | Meaning | TLA+ predicate |
|---|---|---|
| SP1 | The value in effect is never more permissive than the file's | `SP1_NeverMorePermissiveThanFile` |
| SP2 | Outside an update, a value in effect that differs from the file's is reported unsaved, and only the restrictive value is ever unsaved | `SP2_AheadOfFileIsReported` |
| SP3 | A restrictive request is in effect for as long as its save takes | `SP3_RestrictiveInEffectDuringSave` |
| SP4 | The answer matches the state: success, applied and not saved, or failed with nothing changed in effect | `SP4_AnswerMatchesState` |

## What TLC actually verifies

The transitions transcribe
`internal/signerapp/admin/service.go::updateAdminSettingLocked`, which runs
under the store mutation lock:

- `Begin(v)` is the request. `Restricts(v)` is `restricts`: the request is
  for the restrictive value, and that value is not yet in effect or is in
  effect ahead of the file. A restrictive request publishes the value and
  marks the setting unsaved before the save starts
  (`RuntimeConfig.SetUnsaved`).
- `SavePlaced` is the save's rename putting the new file in place
  (`productruntime.SaveStoredSetting`), and `Publish` is memory following it
  with the unsaved mark cleared. A directory flush that fails after the
  rename (`fsutil.ErrPublishedNotDurable`) leaves the new file in place and
  takes the same two steps.
- `SaveFail` is a save that left the old file in place. A restrictive value
  stays in effect and unsaved, answered `applied_not_saved`
  (`protocol.ResultCodeAppliedNotSaved`); any other value was never
  published.
- `Restart` is a restart or a crash at any point of an update. Memory is
  loaded from the file, which holds the old value or the new one.

A signing request reads the value in effect at any moment, without the
store mutation lock, so SP1 and SP3 are invariants over every state, the
ones inside an update included.

The two constants are the two halves of the rule, each load-bearing,
confirmed by mutation:

| Mutation | Result |
|---|---|
| `PermissiveAfterSave = FALSE` (negative control) | SP1 fails in two steps: a change away from the restrictive value is in effect while the file still holds the restrictive one |
| `RestrictiveFirst = FALSE` (negative control) | SP3 fails in two steps: the permissive value stays in effect while the restrictive one is being saved |

## Modeling choices and limits

- One setting. Settings are independent: each has its own unsaved mark, an
  update holds the store mutation lock, and the save rewrites only its own
  key.
- `passphrase_timeout` and `theme` are never restrictive and take the
  permissive path. The headless refusals of `lock_on_disconnect` and
  `passphrase_timeout` come before the rule and are not modeled.
- A hand edit of the file while the signer runs is outside the model. It
  takes effect at the next start, and the signer makes no check for one.
- The normal configuration already exhausts the model's full finite state
  space, so no deep configuration exists for this module; this note is the
  record required by the roadmap working rules.

## How to check

```sh
make formal-test
```

For the focused runs:

```sh
java -jar tla2tools.jar -config docs/formal/setting_publish.cfg \
  docs/formal/setting_publish.tla
java -jar tla2tools.jar -config docs/formal/setting_publish_negative_permissive.cfg \
  docs/formal/setting_publish.tla
java -jar tla2tools.jar -config docs/formal/setting_publish_negative_restrictive.cfg \
  docs/formal/setting_publish.tla
```
