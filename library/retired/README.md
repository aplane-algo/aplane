# Retired Templates

These five LogicSig templates have left the default KeyType Library. New
accounts should use a preset of `aplane.falcon1024-b.v1`.

| Template | File | Replacement preset |
|---|---|---|
| `aplane.falcon1024-allowlist.v1` | `aplane.falcon1024-allowlist.v1.yaml` | Allowlist |
| `aplane.falcon1024-allowlist.v2` | `aplane.falcon1024-allowlist.v2.yaml` | Allowlist |
| `aplane.falcon1024-allowlist-lock.v1` | `aplane.falcon1024-allowlist-lock.v1.yaml` | Locked Allowlist |
| `aplane.corridor.v1` | `aplane.corridor.v1.yaml` | Corridor |
| `aplane.falcon1024-timelock.v1` | `aplane.falcon1024-timelock.v1.yaml` | Timelock |

Retirement changes where the files live, not what they do. Existing accounts
keep working, and an installed template keeps parsing, validating, generating,
and appearing in the KeyType Library.

## Repairing an account

The files stay available so an operator can restore a template that an active
account still needs. The installer copies them to
`<APSIGNER_DATA>/library/retired/`:

```bash
apadmin template import <APSIGNER_DATA>/library/retired/aplane.corridor.v1.yaml
```

Re-importing matches an installed copy. The deprecation comment at the top of
each file is not part of the template definition, so it changes neither the
template fingerprint nor any account address. Keep it outside the `teal` block:
that text is part of the definition.
