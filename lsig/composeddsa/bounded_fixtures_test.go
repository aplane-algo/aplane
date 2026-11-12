// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa

// These template fixtures serve the bounded renderer tests in both test packages.
// They began as the retired library templates, which bounded2 deleted. Each keeps
// that YAML except for its identity, the contract and its rekey setting, so a
// renderer change still shows up against a realistic template.

// FixedAllowlistFixtureYAML uses the framework fixed_allowlist policy, in
// generated mode, with up to 30 recipients and a spending-key rekey.
const FixedAllowlistFixtureYAML = `schema_version: 2
derivation_version: 3
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: generated
publisher: test
family: fixed-allowlist-fixture
version: 1
display_name: "Fixed Allowlist Fixture"
valid_rekey_target: true
description: "Falcon-1024 signature restricted to a fixed set of receiver addresses"
max_opcode_cost: 20000

bounded:
  contract: bounded2
  spend_effects: [pay, axfer, asset_opt_in]
  max_fee: 10000
  rekey: spending_key
  layer3:
    policy: fixed_allowlist
    recipients_parameter: recipients

parameters:
  - name: recipients
    type: address[]
    required: true
    min_items: 1
    max_items: 30
    label: "Allowlisted Addresses"
    description: "Comma-separated Algorand addresses that may receive funds from this Falcon LogicSig"
    placeholder: "ADDR1, ADDR2, ADDR3"
`

// MerkleAllowlistFixtureYAML is a strict template whose author TEAL checks a
// signer-derived Merkle proof against a root compiled from the recipients.
const MerkleAllowlistFixtureYAML = `schema_version: 2
derivation_version: 3
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: strict
publisher: test
family: merkle-allowlist-fixture
version: 1
display_name: "Merkle Allowlist Fixture"
valid_rekey_target: true
description: "Allowlist implementation based on a fixed-depth Merkle root with signer-generated 512-byte proofs."
max_opcode_cost: 20000

bounded:
  contract: bounded2
  spend_effects: [pay, axfer, asset_opt_in]
  max_fee: 10000
  rekey: spending_key
  derived_args:
    - name: merkle_proof
      kind: merkle_allowlist_proof
      parameter: recipients
      max_size: 512

parameters:
  - name: recipients
    label: "Allowlisted Addresses"
    description: "Comma-separated Algorand addresses that may receive funds from this Falcon LogicSig. The signer stores this public list in the key file and generates Merkle proofs automatically when signing."
    type: address[]
    required: true
    min_items: 1
    max_items: 65536
    placeholder: "ADDR1, ADDR2, ADDR3"

template_variables:
  - name: root
    source: parameter
    parameter: recipients
    type: address[]
    constant: byte

teal: |
  // Falcon-1024 Allowlist v2 suffix (runs after base Falcon verification;
  // arg 0 is the Falcon signature, arg 1 is the signer-generated Merkle
  // inclusion proof).
  //
  // Receiver / AssetReceiver must be the sender itself or a member proven by the
  // proof in arg 1. The Merkle tree is fixed-depth 16 over the key-file
  // recipients: unique address public keys sorted ascending, leaves
  // sha256(0x00 || pubkey), padded to 65536 leaves with sha256(0x00), and
  // internal nodes sha256(0x01 || min || max).
  // The bounded1 envelope rejects close-out, clawback, hybrid effects, and
  // transaction types outside its closed transfer surface before this policy.

  txn TypeEnum
  int pay
  ==
  bnz pay_path
  txn TypeEnum
  int axfer
  ==
  bnz asset_path
  err

  // --- asset transfer path ---
  asset_path:
  txn AssetReceiver
  txn Sender
  ==
  bnz allow_asset_receiver
  txn AssetReceiver
  callsub verify_member
  assert

  allow_asset_receiver:
  b end_checks

  // --- payment path ---
  pay_path:
  txn Receiver
  txn Sender
  ==
  bnz allow_pay_receiver
  txn Receiver
  callsub verify_member
  assert

  allow_pay_receiver:
  b end_checks

  // verify_member: [candidate-address] -> [is_member 0/1]
  // leaf = sha256(0x00 || candidate); fold 16 levels with sorted-pair node
  // hashing sha256(0x01 || min || max); compare the result to $root.
  verify_member:
  arg 1
  len
  int 512
  ==
  assert
  pushbytes 0x00
  swap
  concat
  sha256
  arg 1
  int 0
  int 32
  extract3
  callsub combine
  arg 1
  int 32
  int 32
  extract3
  callsub combine
  arg 1
  int 64
  int 32
  extract3
  callsub combine
  arg 1
  int 96
  int 32
  extract3
  callsub combine
  arg 1
  int 128
  int 32
  extract3
  callsub combine
  arg 1
  int 160
  int 32
  extract3
  callsub combine
  arg 1
  int 192
  int 32
  extract3
  callsub combine
  arg 1
  int 224
  int 32
  extract3
  callsub combine
  arg 1
  int 256
  int 32
  extract3
  callsub combine
  arg 1
  int 288
  int 32
  extract3
  callsub combine
  arg 1
  int 320
  int 32
  extract3
  callsub combine
  arg 1
  int 352
  int 32
  extract3
  callsub combine
  arg 1
  int 384
  int 32
  extract3
  callsub combine
  arg 1
  int 416
  int 32
  extract3
  callsub combine
  arg 1
  int 448
  int 32
  extract3
  callsub combine
  arg 1
  int 480
  int 32
  extract3
  callsub combine
  $root
  ==
  retsub

  // combine: [h, sib] -> [sha256(0x01 || min(h,sib) || max(h,sib))]
  combine:
  dup2
  b<
  bnz combine_ordered
  swap
  combine_ordered:
  concat
  pushbytes 0x01
  swap
  concat
  sha256
  retsub

  end_checks:
`

// CustomTimelockFixtureYAML is a strict template whose author TEAL is a round
// timelock. It refuses rekeys: a spending-key rekey never reaches Layer 3, so it
// could leave the account before the unlock round.
const CustomTimelockFixtureYAML = `schema_version: 2
derivation_version: 3
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: strict
publisher: test
family: custom-timelock-fixture
version: 1
display_name: "Custom Timelock Fixture"
valid_rekey_target: true
description: "Falcon-1024 signature gated by round-based timelock"
max_opcode_cost: 20000

bounded:
  contract: bounded2
  spend_effects: [pay, axfer, asset_opt_in]
  max_fee: 10000
  rekey: refused

parameters:
  - name: unlock_round
    label: "Unlock Round"
    description: "Round number after which funds can be withdrawn"
    type: uint64
    required: true
    max_length: 20
    min: 1
    example: "50000000"
    placeholder: "Enter unlock round number"

template_variables:
  - name: unlock_round
    source: parameter
    parameter: unlock_round
    type: uint64
    constant: int

teal: |
  // Timelock check: FirstValid >= unlock_round
  txn FirstValid
  $unlock_round
  >=
  assert
`
