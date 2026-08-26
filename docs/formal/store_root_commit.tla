-------------------------- MODULE store_root_commit --------------------------
EXTENDS Integers, TLC

(***************************************************************************
Atomic store-root model. One durable record carries generation selection,
keyring epoch, and current term. VerifyPins=FALSE is the deliberate negative
control: substitution after the outgoing seal can then reach the new root
without exact input authorization and violates NoUnpinnedPromotion.
***************************************************************************)

CONSTANTS OldGen, NewGen, OldEpoch, NewEpoch, OldTerm, NewTerm, VerifyPins

VARIABLES rootGen, rootEpoch, rootTerm,
          published, publicationDurable, outgoingSealed,
          substituted, promotionPinned, candidateBuilt,
          rootVisible, rootDurable, quarantined

vars == <<rootGen, rootEpoch, rootTerm,
          published, publicationDurable, outgoingSealed,
          substituted, promotionPinned, candidateBuilt,
          rootVisible, rootDurable, quarantined>>

OldRoot == <<OldGen, OldEpoch, OldTerm>>
NewRoot == <<NewGen, NewEpoch, NewTerm>>
Init ==
  /\ rootGen = OldGen
  /\ rootEpoch = OldEpoch
  /\ rootTerm = OldTerm
  /\ published = FALSE
  /\ publicationDurable = FALSE
  /\ outgoingSealed = FALSE
  /\ substituted = FALSE
  /\ promotionPinned = FALSE
  /\ candidateBuilt = FALSE
  /\ rootVisible = FALSE
  /\ rootDurable = FALSE
  /\ quarantined = FALSE

Publish ==
  /\ ~published
  /\ published' = TRUE
  /\ UNCHANGED <<rootGen, rootEpoch, rootTerm, publicationDurable,
                  outgoingSealed, substituted, promotionPinned,
                  candidateBuilt, rootVisible, rootDurable, quarantined>>

SyncPublication ==
  /\ published
  /\ ~publicationDurable
  /\ publicationDurable' = TRUE
  /\ UNCHANGED <<rootGen, rootEpoch, rootTerm, published,
                  outgoingSealed, substituted, promotionPinned,
                  candidateBuilt, rootVisible, rootDurable, quarantined>>

SealOutgoing ==
  /\ publicationDurable
  /\ ~outgoingSealed
  /\ outgoingSealed' = TRUE
  /\ UNCHANGED <<rootGen, rootEpoch, rootTerm, published,
                  publicationDurable, substituted, promotionPinned,
                  candidateBuilt, rootVisible, rootDurable, quarantined>>

SubstituteInput ==
  /\ outgoingSealed
  /\ ~candidateBuilt
  /\ substituted' = TRUE
  /\ UNCHANGED <<rootGen, rootEpoch, rootTerm, published,
                  publicationDurable, outgoingSealed, promotionPinned,
                  candidateBuilt, rootVisible, rootDurable, quarantined>>

BuildCandidate ==
  /\ publicationDurable
  /\ outgoingSealed
  /\ ~candidateBuilt
  /\ (~VerifyPins \/ ~substituted)
  /\ candidateBuilt' = TRUE
  /\ promotionPinned' = ~substituted
  /\ UNCHANGED <<rootGen, rootEpoch, rootTerm, published,
                  publicationDurable, outgoingSealed, substituted,
                  rootVisible, rootDurable, quarantined>>

RenameRoot ==
  /\ candidateBuilt
  /\ ~rootVisible
  /\ ~quarantined
  /\ (~VerifyPins \/ promotionPinned)
  /\ rootGen' = NewGen
  /\ rootEpoch' = NewEpoch
  /\ rootTerm' = NewTerm
  /\ rootVisible' = TRUE
  /\ UNCHANGED <<published, publicationDurable, outgoingSealed,
                  substituted, promotionPinned, candidateBuilt,
                  rootDurable, quarantined>>

SyncRoot ==
  /\ rootVisible
  /\ ~rootDurable
  /\ rootDurable' = TRUE
  /\ UNCHANGED <<rootGen, rootEpoch, rootTerm, published,
                  publicationDurable, outgoingSealed, substituted,
                  promotionPinned, candidateBuilt, rootVisible, quarantined>>

CrashBeforeRename ==
  /\ ~rootVisible
  /\ <<rootGen, rootEpoch, rootTerm>> = OldRoot
  /\ UNCHANGED vars

ReconcileOldRoot ==
  /\ <<rootGen, rootEpoch, rootTerm>> = OldRoot
  /\ publicationDurable
  /\ ~quarantined
  /\ quarantined' = TRUE
  /\ UNCHANGED <<rootGen, rootEpoch, rootTerm, published,
                  publicationDurable, outgoingSealed, substituted,
                  promotionPinned, candidateBuilt, rootVisible, rootDurable>>

\* An operator can restore an older authentic root file after the successor
\* was committed. The newer complete directory then has the same shape as a
\* crashed-mint publication and must be quarantined, never deleted or adopted.
RestoreAuthenticOldRoot ==
  /\ <<rootGen, rootEpoch, rootTerm>> = NewRoot
  /\ rootDurable
  /\ rootGen' = OldGen
  /\ rootEpoch' = OldEpoch
  /\ rootTerm' = OldTerm
  /\ rootVisible' = FALSE
  /\ rootDurable' = TRUE
  /\ quarantined' = FALSE
  /\ UNCHANGED <<published, publicationDurable, outgoingSealed,
                  substituted, promotionPinned, candidateBuilt>>

Next == Publish \/ SyncPublication \/ SealOutgoing \/ SubstituteInput \/
        BuildCandidate \/ RenameRoot \/ SyncRoot \/ CrashBeforeRename \/
        ReconcileOldRoot \/ RestoreAuthenticOldRoot

Spec == Init /\ [][Next]_vars

TypeOK ==
  /\ rootGen \in {OldGen, NewGen}
  /\ rootEpoch \in {OldEpoch, NewEpoch}
  /\ rootTerm \in {OldTerm, NewTerm}
  /\ published \in BOOLEAN
  /\ publicationDurable \in BOOLEAN
  /\ outgoingSealed \in BOOLEAN
  /\ substituted \in BOOLEAN
  /\ promotionPinned \in BOOLEAN
  /\ candidateBuilt \in BOOLEAN
  /\ rootVisible \in BOOLEAN
  /\ rootDurable \in BOOLEAN
  /\ quarantined \in BOOLEAN

S1_OneSelectedAuthority ==
  /\ rootGen = OldGen => <<rootEpoch, rootTerm>> = <<OldEpoch, OldTerm>>
  /\ rootGen = NewGen => <<rootEpoch, rootTerm>> = <<NewEpoch, NewTerm>>
S2_AtomicCutover ==
  (rootEpoch = OldEpoch) <=> (rootTerm = OldTerm)
S3_PublishedCompleteness == rootGen = NewGen => publicationDurable
S4_NewTermCurrentState == rootGen = NewGen => rootTerm = NewTerm
S5_NoUnpinnedPromotion == rootGen = NewGen => promotionPinned
S13_NonDestructiveAmbiguity ==
  quarantined => <<rootGen, rootEpoch, rootTerm>> = OldRoot
S14_QuarantineNonAuthority == quarantined => rootGen # NewGen

=============================================================================
