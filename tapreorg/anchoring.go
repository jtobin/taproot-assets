package tapreorg

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

var (
	// ErrEmptyTriggerSet is returned when a trigger set is
	// constructed with no outpoints.
	ErrEmptyTriggerSet = errors.New("trigger set must not be empty")

	// ErrDuplicateTrigger is returned when a trigger set is
	// constructed with a repeated outpoint.
	ErrDuplicateTrigger = errors.New("duplicate trigger outpoint")

	// ErrIncompleteWitness is returned when a witness is
	// constructed from incomplete location data.
	ErrIncompleteWitness = errors.New("witness requires a " +
		"transaction and a complete chain location")
)

// SiteID identifies a subsystem that stakes local state on chain
// outcomes and registers anchorings with the watcher. Site IDs are
// stable strings; they are persisted with each anchoring and used to
// route signals back to the owning site's handlers after a restart.
type SiteID string

// AnchoringID is the registry-assigned identifier of an anchoring. It
// is a distinct type so that it cannot be confused with other integral
// identifiers.
type AnchoringID int64

// Verdict is a site's judgment of a candidate spending transaction:
// either the candidate realizes the site's anchoring (possibly in a
// different form than originally broadcast), or it is a foreign
// transaction that forecloses it.
type Verdict uint8

const (
	// VerdictSatisfies indicates the candidate realizes the
	// anchoring.
	VerdictSatisfies Verdict = 0

	// VerdictForeign indicates the candidate forecloses the
	// anchoring.
	VerdictForeign Verdict = 1
)

// NewVerdict converts a raw integer (e.g. from a database row) into a
// Verdict, rejecting unknown values.
func NewVerdict(v uint8) (Verdict, error) {
	switch Verdict(v) {
	case VerdictSatisfies:
		return VerdictSatisfies, nil

	case VerdictForeign:
		return VerdictForeign, nil

	default:
		return 0, fmt.Errorf("unknown verdict %d", v)
	}
}

// String returns a human-readable verdict.
func (v Verdict) String() string {
	switch v {
	case VerdictSatisfies:
		return "satisfies"

	case VerdictForeign:
		return "foreign"

	default:
		return fmt.Sprintf("unknown<%d>", uint8(v))
	}
}

// TriggerOutPoint is one outpoint of an anchoring's trigger set,
// together with the script and height hint needed to open a spend
// subscription on it.
type TriggerOutPoint struct {
	// OutPoint is the outpoint whose spending constitutes (or
	// forecloses) the anchoring event.
	OutPoint wire.OutPoint

	// PkScript is the output script of the outpoint.
	PkScript []byte

	// HeightHint is the earliest height at which the outpoint
	// could have been spent.
	HeightHint uint32
}

// TriggerSet is the non-empty, duplicate-free set of outpoints whose
// spending the watcher observes for an anchoring. Identity of the
// anchoring lives here: any admissible witness must spend the entire
// set (the whole-set rule), so a satisfying spend and a foreign spend
// can never coexist on a single chain.
//
// The zero value is invalid; values in circulation originate from
// NewTriggerSet and are therefore well-formed by provenance.
type TriggerSet struct {
	outpoints []TriggerOutPoint
}

// NewTriggerSet builds a trigger set, rejecting empty sets and
// duplicate outpoints.
func NewTriggerSet(points []TriggerOutPoint) (TriggerSet, error) {
	if len(points) == 0 {
		return TriggerSet{}, ErrEmptyTriggerSet
	}

	seen := make(map[wire.OutPoint]struct{}, len(points))
	copied := make([]TriggerOutPoint, len(points))
	for i, p := range points {
		if _, ok := seen[p.OutPoint]; ok {
			return TriggerSet{}, fmt.Errorf("%w: %v",
				ErrDuplicateTrigger, p.OutPoint)
		}
		seen[p.OutPoint] = struct{}{}

		copied[i] = TriggerOutPoint{
			OutPoint:   p.OutPoint,
			PkScript:   append([]byte(nil), p.PkScript...),
			HeightHint: p.HeightHint,
		}
	}

	return TriggerSet{outpoints: copied}, nil
}

// OutPoints returns a copy of the trigger outpoints.
func (t TriggerSet) OutPoints() []TriggerOutPoint {
	out := make([]TriggerOutPoint, len(t.outpoints))
	for i, p := range t.outpoints {
		out[i] = TriggerOutPoint{
			OutPoint:   p.OutPoint,
			PkScript:   append([]byte(nil), p.PkScript...),
			HeightHint: p.HeightHint,
		}
	}

	return out
}

// Contains reports whether the given outpoint is part of the trigger
// set.
func (t TriggerSet) Contains(op wire.OutPoint) bool {
	for _, p := range t.outpoints {
		if p.OutPoint == op {
			return true
		}
	}

	return false
}

// Len returns the number of trigger outpoints.
func (t TriggerSet) Len() int {
	return len(t.outpoints)
}

// Witness is a transaction located on the chain: the transaction
// itself plus the block hash, height and transaction index of its
// inclusion. A witness for an anchoring is a satisfying spend of its
// trigger set; the same type also locates foreign spends.
//
// The zero value is invalid; values in circulation originate from
// NewWitness (or the phase decoder, which routes through it) and are
// therefore fully located by provenance: a partially-located witness
// is unrepresentable.
type Witness struct {
	txHash    chainhash.Hash
	blockHash chainhash.Hash
	height    uint32
	txIndex   uint32
	tx        *wire.MsgTx
}

// NewWitness builds a witness from a transaction and its complete
// chain location. The transaction is deep-copied.
func NewWitness(tx *wire.MsgTx, blockHash chainhash.Hash, height uint32,
	txIndex uint32) (Witness, error) {

	if tx == nil || height == 0 {
		return Witness{}, ErrIncompleteWitness
	}

	txCopy := tx.Copy()

	return Witness{
		txHash:    txCopy.TxHash(),
		blockHash: blockHash,
		height:    height,
		txIndex:   txIndex,
		tx:        txCopy,
	}, nil
}

// TxHash returns the hash of the located transaction.
func (w Witness) TxHash() chainhash.Hash {
	return w.txHash
}

// BlockHash returns the hash of the block containing the transaction.
func (w Witness) BlockHash() chainhash.Hash {
	return w.blockHash
}

// Height returns the height of the block containing the transaction.
func (w Witness) Height() uint32 {
	return w.height
}

// TxIndex returns the index of the transaction within its block.
func (w Witness) TxIndex() uint32 {
	return w.txIndex
}

// Tx returns a deep copy of the located transaction.
func (w Witness) Tx() *wire.MsgTx {
	return w.tx.Copy()
}

// WitnessContext extracts the given phase's witness candidate from the
// anchoring's Spends, with its block enrichment attached. The witness
// used is the phase's (current location), but the enrichment comes
// from the recorded candidate — the phase carries the witness
// identity, and the candidate carries the block header and merkle
// proof sensing enriched into it.
//
// Every site's Buried and Witnessed handler needs the same
// combination: mint reconfirmation, porter proof rebuilding, receive
// tip patching, supply-commit finalization. The pattern extracts here
// so the four sites don't each maintain their own copy of the same
// enrichment-lookup logic.
//
// Returns an error if the phase is not a witness-bearing phase, if
// the phase's witness is not among the anchoring's candidates, or if
// the matching candidate is missing block enrichment (a wiring
// invariant sensing is expected to have upheld).
func WitnessContext(anchoring *Anchoring,
	phase Phase) (*CandidateSpend, error) {

	var witness Witness
	switch p := phase.(type) {
	case Witnessed:
		witness = p.W

	case Buried:
		witness = p.W

	default:
		return nil, fmt.Errorf("no witness in phase %v", phase)
	}

	for idx := range anchoring.Spends {
		candidate := &anchoring.Spends[idx]
		if candidate.W.TxHash() != witness.TxHash() {
			continue
		}
		if candidate.BlockHeader == nil ||
			candidate.MerkleProof == nil {

			return nil, fmt.Errorf("witness %v lacks block "+
				"enrichment", witness.TxHash())
		}

		// Use the phase's witness location (the current one) with
		// the candidate's enrichment.
		enriched := *candidate
		enriched.W = witness

		return &enriched, nil
	}

	return nil, fmt.Errorf("witness %v not among candidates",
		witness.TxHash())
}

// ForeignSpend is an observed foreign spend of a trigger outpoint: the
// spent outpoint plus the located spending transaction.
type ForeignSpend struct {
	// SpentOutPoint is the trigger outpoint the foreign
	// transaction spends.
	SpentOutPoint wire.OutPoint

	// W locates the foreign spending transaction on chain.
	W Witness
}

// VersionedBlob is the envelope in which all site-owned opaque data
// (match data, site payloads, effect payloads) travels and persists.
// The version tags the site's encoding so that a site can decode
// every version it has ever written.
type VersionedBlob struct {
	// Version is the site-owned encoding version of Data.
	Version uint16

	// Data is the opaque payload. The watcher never interprets it.
	Data []byte
}

// RegistrationSpec is the data a site supplies to register an
// anchoring. It contains only data — the no-closures rule is
// structural.
type RegistrationSpec struct {
	// Site is the registering site.
	Site SiteID

	// Triggers is the trigger set; see TriggerSet for the identity
	// semantics it carries.
	Triggers TriggerSet

	// MatchData is handed back to the site's predicate when a
	// candidate spend appears.
	MatchData VersionedBlob

	// Payload carries whatever the site needs to patch, finalize
	// or reverse its speculation. It must identify everything the
	// site keyed to the anchoring.
	Payload VersionedBlob

	// Threshold is the confirmation depth at which this site
	// considers an outcome final (act-confirmed).
	Threshold uint32

	// MatchKey is the site's per-registration identity key. Two
	// registrations by the same site with the same MatchKey refer
	// to the same essential fact; the registry enforces this via a
	// unique index and sites use it to look up their own existing
	// anchorings in O(1) via LookupByMatchKey. Sites use the
	// anchor/genesis/commit txid as the key; empty is allowed for
	// tests and legacy rows and disables the uniqueness constraint.
	MatchKey []byte

	// SeedCandidate, when set, is a fully-enriched candidate spend
	// the caller already knows about (e.g. a received proof file's
	// tip anchor tx). The registry inserts it at registration and
	// the sensor immediately subscribes to its conf events for
	// act-certification and re-org detection — no spend-side
	// discovery is required. Registrations that set SeedCandidate
	// may pass an empty trigger set: the seed IS the witnessing
	// transaction, and there is no prior outpoint for any foreign
	// spender to foreclose against.
	SeedCandidate *CandidateSpend
}

// Validate checks the spec's value-level invariants.
func (s *RegistrationSpec) Validate() error {
	if s.Site == "" {
		return errors.New("registration requires a site ID")
	}
	if s.Triggers.Len() == 0 && s.SeedCandidate == nil {
		return ErrEmptyTriggerSet
	}
	if s.Threshold == 0 {
		return errors.New("registration requires a threshold " +
			"of at least one confirmation")
	}
	if s.SeedCandidate != nil {
		if !s.SeedCandidate.OnChain {
			return errors.New("seed candidate must be on-chain")
		}
		if s.SeedCandidate.BlockHeader == nil {
			return errors.New("seed candidate must carry its " +
				"block header")
		}
		if s.SeedCandidate.MerkleProof == nil {
			return errors.New("seed candidate must carry its " +
				"merkle proof")
		}
	}

	return nil
}

// Anchoring is one act of staking local state on a future chain
// outcome, made first-class and durable. It is the unit of
// registration, sensing and delivery.
type Anchoring struct {
	// ID is the registry-assigned identifier.
	ID AnchoringID

	// Site is the owning site.
	Site SiteID

	// Triggers is the trigger set.
	Triggers TriggerSet

	// MatchData is the site's opaque predicate input.
	MatchData VersionedBlob

	// Payload is the site's opaque repair/finalize data.
	Payload VersionedBlob

	// MatchKey is the site's per-registration identity key; see
	// RegistrationSpec.MatchKey.
	MatchKey []byte

	// Threshold is the act-confirmation depth for this anchoring.
	Threshold uint32

	// CreatedHeight is the best height at registration time.
	CreatedHeight uint32

	// Phase is the sensed phase: the registry's derived truth.
	Phase Phase

	// DeliveredPhase is the last phase the owning site has durably
	// acknowledged. The site is converged when it equals Phase.
	DeliveredPhase Phase

	// Stuck indicates delivery has failed repeatedly; retries
	// continue at low frequency, and the condition is surfaced.
	Stuck bool

	// DeliveryAttempts counts failed delivery attempts since the
	// last successful delivery.
	DeliveryAttempts uint32

	// Spends is the chain view: every candidate spend observed for
	// this anchoring, on-chain or not.
	Spends []CandidateSpend
}
