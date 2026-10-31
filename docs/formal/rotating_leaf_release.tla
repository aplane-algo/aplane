------------------------- MODULE rotating_leaf_release -------------------------
EXTENDS Naturals, FiniteSets, TLC

(***************************************************************************
Rotating one-time leaf model: which leaf a rotating stage signs with, and
which state that choice depends on.

A rotating account of a leaf family (rotatingkey.Profile.LeavesPerStage > 1,
today the XMSS triple) holds several one-time leaves per stage. Signing the
same leaf for two different transactions spends a one-time key twice. The
signer therefore chooses the leaf from the stage's release history:

  - a transaction the stage already released keeps its leaf (an identical
    retry reproduces the identical signature);
  - otherwise the TxID's pick, advanced to the first unused leaf, wrapping;
  - when every leaf is used the TxID's pick is reused and reported. State
    chooses the leaf, never whether to sign.

The history lives in process memory (ReleaseMemory) and is rebuilt from the
audit log at unlock. The model checks that, outside the named loss cases, the
memory is a complete record of the stage's releases whenever the signer can
sign, so the leaf choice never reuses a leaf while an unused one remains.

Three guards keep the memory complete, and one modeled loss class is excused
explicitly:

  WaitForRestore   a leaf-family sign waits (AwaitRestored) until the audit
                   restore after an unlock has finished, so it never chooses
                   a leaf from an empty memory.
  SeqGuard         a status pass that reads the chain clears an account's
                   memory only if no release was recorded after the pass read
                   the chain (Record/Seq/clearIfUnchanged), so a stale
                   observation never erases a newer release.
  MergeAudited     a restore merges the audited releases into the memory (it
                   keeps every leaf either side knows) instead of replacing
                   it.

  Loss (not a guard): the audit write is best effort (a failure is reported,
  not fatal), the log may rotate past old entries, and a restore may fail.
  Each sets the ghost flag lossy. LF1 and LF2 are claimed only while lossy
  is FALSE: the leaf scheme is an interlock over the history the signer can
  see, not a guarantee against a history the signer lost.

The negative controls turn off WaitForRestore (the memory is empty when the
first post-unlock sign picks a leaf) and SeqGuard (a stale observation erases
the current release), each with every loss source off, and TLC reproduces
the leaf reuse under a complete history.

Scope: one account, one signer. Several signers sharing a seed and no memory
collide with probability one in LeavesPerStage by design (chooseLeaf) and are
not modeled. Stateless-hash families keep no leaf history and are not
modeled. Chain validity windows, expiry, and the stage-table recovery grants
are not modeled; only release memory, restore and observation are.

Code anchors:
  - Sign transcribes internal/signerapp/signing/rotating_flow.go
    SignRotatingWithContext (AwaitRestored before the account lock, chooseLeaf
    from Releases.Get under it, audit write, Releases.Record) and chooseLeaf.
  - Land is the release (or any transaction) confirming: the live authorizer
    moves to the next stage (rule 1 reads it under the lock).
  - Unlock/RestoreBegin/RestoreApply/RestoreFail/Lock transcribe
    ReleaseMemory.Reset/Restoring/RecordAudited/Restored/RestoredAll and
    Service.RebuildReleaseMemory in rotating_release.go.
  - Observe/ApplyObservation transcribe the stage-table pass's ObservedSeq
    capture (rotating_tables.go) and Service.RotatingStatus clearIfUnchanged.

See FORMAL_TLA_ROTATING_LEAF_RELEASE_MODEL.md for the prose companion.
***************************************************************************)

CONSTANTS
    WaitForRestore,   \* BOOLEAN: sign waits for the post-unlock restore
    SeqGuard,         \* BOOLEAN: observation clears only unchanged memory
    AuditMayFail,     \* BOOLEAN: the audit write may fail (best effort)
    AuditMayLose,     \* BOOLEAN: the log may drop an old entry
    RestoreMayFail,   \* BOOLEAN: the restore may fail and open the wait
    NLeaves,          \* leaves per stage
    NTx,              \* distinct transactions per stage (TxID pick = tx % NLeaves)
    MaxStage,         \* the chain stage ranges over 0..MaxStage
    MaxSeq            \* bound on Record events (keeps the state space finite)

Leaves == 0..(NLeaves - 1)
Txs == 1..NTx
None == 99  \* no stage (outside 0..MaxStage)

\* A release is <<stage, leaf, tx>>; a memory entry within a stage is <<leaf, tx>>.

VARIABLES
    chain,       \* the stage the live authorizer is at
    phase,       \* "locked" | "armed" | "restoring" | "open"
    truth,       \* ghost: every release whose signature left the signer
    audit,       \* the durable audit log's release entries
    snap,        \* the entries the restore read at its start
    memStage,    \* the remembered release's stage, or None
    memRecs,     \* the leaves it lists, as <<leaf, tx>>
    memSeq,      \* the sequence number stamped on the entry
    seq,         \* the memory's last-assigned sequence number
    obsStage,    \* a status pass's chain read awaiting its clear step, or None
    obsSeq,      \* the Seq captured before that read
    lossy,       \* ghost: a loss source fired (audit write failed, entry lost, restore failed)
    bad,         \* ghost: a leaf was reused for a different transaction while a leaf was unused
    drift        \* ghost: a retried transaction signed on a different leaf

vars == <<chain, phase, truth, audit, snap, memStage, memRecs, memSeq, seq,
          obsStage, obsSeq, lossy, bad, drift>>

Init ==
    /\ chain = 0
    /\ phase = "locked"
    /\ truth = {}
    /\ audit = {}
    /\ snap = {}
    /\ memStage = None
    /\ memRecs = {}
    /\ memSeq = 0
    /\ seq = 0
    /\ obsStage = None
    /\ obsSeq = 0
    /\ lossy = FALSE
    /\ bad = FALSE
    /\ drift = FALSE

----------------------------------------------------------------------------
(* Leaf choice (chooseLeaf) *)

RecsAt(set, s) == {<<r[2], r[3]>> : r \in {x \in set : x[1] = s}}

UsedLeaves(recs) == {r[1] : r \in recs}

\* The leaf this transaction already signed with, per the given records.
SameLeaf(recs, tx) == {r[1] : r \in {x \in recs : x[2] = tx}}

\* The first unused leaf at or after the TxID's pick, wrapping.
FirstUnused(recs, tx) ==
    LET pick == tx % NLeaves
        unused == Leaves \ UsedLeaves(recs)
        i == CHOOSE k \in 0..(NLeaves - 1) :
                /\ ((pick + k) % NLeaves) \in unused
                /\ \A j \in 0..(k - 1) : ((pick + j) % NLeaves) \notin unused
    IN  (pick + i) % NLeaves

ChooseLeaf(recs, tx) ==
    IF SameLeaf(recs, tx) # {} THEN CHOOSE l \in SameLeaf(recs, tx) : TRUE
    ELSE IF Leaves \ UsedLeaves(recs) = {} THEN tx % NLeaves
    ELSE FirstUnused(recs, tx)

----------------------------------------------------------------------------
(* Signing and landing *)

\* Sign releases a signature for transaction tx from the current stage. It
\* needs an unlocked signer and, with WaitForRestore, a finished restore.
\* The leaf comes from the memory only when the memory is about this stage.
Sign(tx) ==
    /\ chain < MaxStage
    /\ seq < MaxSeq
    /\ IF WaitForRestore THEN phase = "open" ELSE phase # "locked"
    /\ LET prior == IF memStage = chain THEN memRecs ELSE {}
           leaf == ChooseLeaf(prior, tx)
           rel == <<chain, leaf, tx>>
           atStage == RecsAt(truth, chain)
           conflict == \E r \in atStage : r[1] = leaf /\ r[2] # tx
           unusedInTruth == (Leaves \ UsedLeaves(atStage)) # {}
           retryDrift == \E r \in atStage : r[2] = tx /\ r[1] # leaf
       IN  /\ truth' = truth \cup {rel}
           /\ bad' = (bad \/ (conflict /\ unusedInTruth))
           /\ drift' = (drift \/ retryDrift)
           /\ \/ /\ audit' = audit \cup {rel}
                 /\ lossy' = lossy
              \/ /\ AuditMayFail
                 /\ audit' = audit
                 /\ lossy' = TRUE
           /\ memStage' = chain
           /\ memRecs' = prior \cup {<<leaf, tx>>}
           /\ seq' = seq + 1
           /\ memSeq' = seq + 1
    /\ UNCHANGED <<chain, phase, snap, obsStage, obsSeq>>

\* Land is a released transaction confirming: the authorizer moves on.
Land ==
    /\ chain < MaxStage
    /\ RecsAt(truth, chain) # {}
    /\ chain' = chain + 1
    /\ UNCHANGED <<phase, truth, audit, snap, memStage, memRecs, memSeq, seq,
                   obsStage, obsSeq, lossy, bad, drift>>

----------------------------------------------------------------------------
(* Lock, unlock and the audit restore *)

\* Lock forgets the memory entirely (ReleaseMemory.Reset on the next unlock;
\* the process memory does not survive). A restore in flight is abandoned.
Lock ==
    /\ phase # "locked"
    /\ phase' = "locked"
    /\ memStage' = None
    /\ memRecs' = {}
    /\ UNCHANGED <<chain, truth, audit, snap, memSeq, seq, obsStage, obsSeq,
                   lossy, bad, drift>>

\* Unlock arms the memory: every account is held until the log is read.
Unlock ==
    /\ phase = "locked"
    /\ phase' = "armed"
    /\ UNCHANGED <<chain, truth, audit, snap, memStage, memRecs, memSeq, seq,
                   obsStage, obsSeq, lossy, bad, drift>>

\* RestoreBegin reads the log (Restoring). With no entry for the account
\* nothing is pending and the wait opens at once.
RestoreBegin ==
    /\ phase = "armed"
    /\ snap' = audit
    /\ phase' = IF audit = {} THEN "open" ELSE "restoring"
    /\ UNCHANGED <<chain, truth, audit, memStage, memRecs, memSeq, seq,
                   obsStage, obsSeq, lossy, bad, drift>>

\* The audited release for the account lists every leaf the log holds for
\* the stage it names: the highest stage in the snapshot.
SnapStage == CHOOSE s \in {x[1] : x \in snap} :
                 \A t \in {x[1] : x \in snap} : t <= s

\* RestoreApply is RecordAudited then Restored. The merge keeps the newer
\* side: an entry from a later stage than the log's wins; an entry from the
\* same stage keeps every leaf either side knows; an older or absent entry
\* is replaced by the audited stage. Without MergeAudited (not modeled as a
\* switch: the code always merges) a same-stage entry would be replaced.
RestoreApply ==
    /\ phase = "restoring"
    /\ snap # {}
    /\ seq < MaxSeq
    /\ LET audited == RecsAt(snap, SnapStage)
       IN  IF memStage # None /\ memStage > SnapStage
           THEN UNCHANGED <<memStage, memRecs>>
           ELSE IF memStage = SnapStage
                THEN /\ memStage' = memStage
                     /\ memRecs' = memRecs \cup audited
                ELSE /\ memStage' = SnapStage
                     /\ memRecs' = audited
    /\ seq' = seq + 1
    /\ memSeq' = seq + 1
    /\ phase' = "open"
    /\ UNCHANGED <<chain, truth, audit, snap, obsStage, obsSeq, lossy, bad, drift>>

\* RestoreFail: the stage addresses could not be derived, or the restore was
\* cancelled. The wait opens (Restored/RestoredAll) without a record.
RestoreFail ==
    /\ RestoreMayFail
    /\ phase = "restoring"
    /\ phase' = "open"
    /\ lossy' = TRUE
    /\ UNCHANGED <<chain, truth, audit, snap, memStage, memRecs, memSeq, seq,
                   obsStage, obsSeq, bad, drift>>

\* AuditLose: the log rotated past an old entry, or the file lost it.
AuditLose ==
    /\ AuditMayLose
    /\ \E r \in audit :
           /\ audit' = audit \ {r}
           /\ lossy' = TRUE
    /\ UNCHANGED <<chain, phase, truth, snap, memStage, memRecs, memSeq, seq,
                   obsStage, obsSeq, bad, drift>>

----------------------------------------------------------------------------
(* The status pass *)

\* Observe is the stage-table pass capturing Seq and then reading the chain.
Observe ==
    /\ obsStage = None
    /\ obsStage' = chain
    /\ obsSeq' = seq
    /\ UNCHANGED <<chain, phase, truth, audit, snap, memStage, memRecs, memSeq,
                   seq, lossy, bad, drift>>

\* ApplyObservation is RotatingStatus after the read: an entry whose stage is
\* not the one the chain read showed is cleared, unless (SeqGuard) a release
\* was recorded after the read.
ApplyObservation ==
    /\ obsStage # None
    /\ obsStage' = None
    /\ IF memStage # None /\ memStage # obsStage /\ (~SeqGuard \/ memSeq <= obsSeq)
       THEN /\ memStage' = None
            /\ memRecs' = {}
       ELSE UNCHANGED <<memStage, memRecs>>
    /\ UNCHANGED <<chain, phase, truth, audit, snap, memSeq, seq, obsSeq,
                   lossy, bad, drift>>

----------------------------------------------------------------------------
Next ==
    \/ \E tx \in Txs : Sign(tx)
    \/ Land
    \/ Lock
    \/ Unlock
    \/ RestoreBegin
    \/ RestoreApply
    \/ RestoreFail
    \/ AuditLose
    \/ Observe
    \/ ApplyObservation

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
(* Invariants *)

TypeOK ==
    /\ chain \in 0..MaxStage
    /\ phase \in {"locked", "armed", "restoring", "open"}
    /\ truth \subseteq (0..MaxStage) \X Leaves \X Txs
    /\ audit \subseteq truth
    /\ memStage \in ({None} \cup (0..MaxStage))
    /\ obsStage \in ({None} \cup (0..MaxStage))
    /\ memSeq \in 0..MaxSeq
    /\ seq \in 0..MaxSeq
    /\ lossy \in BOOLEAN /\ bad \in BOOLEAN /\ drift \in BOOLEAN

\* The memory only ever lists releases that really happened.
MemoryIsTruthful ==
    memStage # None =>
        \A r \in memRecs : <<memStage, r[1], r[2]>> \in truth

\* LF1: while no loss source has fired, a leaf is never reused for a
\* different transaction while an unused leaf remains in the stage.
LF1_NoReuseBeforeExhaustion == ~lossy => ~bad

\* LF2: while no loss source has fired, a retry of a released transaction
\* reuses its leaf, so an identical retry reproduces the identical signature.
LF2_RetryKeepsLeaf == ~lossy => ~drift

\* LF3: whenever the signer can sign (open), and nothing was lost, the memory
\* lists every release the live stage has made. This is why LF1 holds.
LF3_MemoryCompleteWhenOpen ==
    (phase = "open" /\ ~lossy /\ RecsAt(truth, chain) # {}) =>
        (memStage = chain /\ RecsAt(truth, chain) \subseteq memRecs)

Safety ==
    /\ TypeOK
    /\ MemoryIsTruthful
    /\ LF1_NoReuseBeforeExhaustion
    /\ LF2_RetryKeepsLeaf
    /\ LF3_MemoryCompleteWhenOpen

=============================================================================
