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

Next == Publish \/ SyncPublication \/ SealOutgoing \/ SubstituteInput \/
        BuildCandidate \/ RenameRoot \/ SyncRoot \/ CrashBeforeRename \/
        ReconcileOldRoot

Spec == Init /\ [][Next]_vars

TypeOK ==
  /\ <<rootGen, rootEpoch, rootTerm>> \in {OldRoot, NewRoot}
  /\ published \in BOOLEAN
  /\ publicationDurable \in BOOLEAN
  /\ outgoingSealed \in BOOLEAN
  /\ substituted \in BOOLEAN
  /\ promotionPinned \in BOOLEAN
  /\ candidateBuilt \in BOOLEAN
  /\ rootVisible \in BOOLEAN
  /\ rootDurable \in BOOLEAN
  /\ quarantined \in BOOLEAN

S1_OneSelectedAuthority == <<rootGen, rootEpoch, rootTerm>> \in {OldRoot, NewRoot}
S2_AtomicCutover ==
  <<rootGen, rootEpoch, rootTerm>> = OldRoot \/
  <<rootGen, rootEpoch, rootTerm>> = NewRoot
S3_PublishedCompleteness == rootGen = NewGen => publicationDurable
S4_NewTermCurrentState == rootGen = NewGen => rootTerm = NewTerm
S5_NoUnpinnedPromotion == rootGen = NewGen => promotionPinned
S13_NonDestructiveAmbiguity ==
  quarantined => <<rootGen, rootEpoch, rootTerm>> = OldRoot
S14_QuarantineNonAuthority == quarantined => rootGen # NewGen

=============================================================================
