package tapcustody

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapreorg"
)

const (
	// ReceiveSiteID identifies the receive side (custodian and RPC
	// proof import) as a re-org watcher site.
	ReceiveSiteID tapreorg.SiteID = "tapcustody.receiver"

	// receiveBlobVersion versions the receive side's anchoring
	// blobs.
	receiveBlobVersion = 1
)

// ReceiveAnchoringLog is the transaction-scoped persistence surface
// the receive site drives from its handlers, implemented by the asset
// store.
type ReceiveAnchoringLog interface {
	// ApplyReceiveReconfirm converges received state to a
	// (re)confirmed anchor.
	ApplyReceiveReconfirm(ctx context.Context, q *sqlc.Queries,
		anchorTxid chainhash.Hash, blockHash chainhash.Hash,
		blockHeight, txIndex uint32, header wire.BlockHeader,
		merkle proof.TxMerkleProof) error

	// ApplyReceiveUnconfirm withdraws the recorded confirmation.
	ApplyReceiveUnconfirm(ctx context.Context, q *sqlc.Queries,
		anchorTxid chainhash.Hash) error

	// ApplyReceiveAbandonment compensates an abandoned receive.
	ApplyReceiveAbandonment(ctx context.Context, q *sqlc.Queries,
		anchorTxid chainhash.Hash, resetStatus int16) error
}

// encodeReceiveBlob encodes the receive site's anchoring blob: the
// anchor transaction the received proofs are keyed to.
func encodeReceiveBlob(anchorTxid chainhash.Hash) tapreorg.VersionedBlob {
	return tapreorg.VersionedBlob{
		Version: receiveBlobVersion,
		Data:    anchorTxid[:],
	}
}

// decodeReceiveBlob decodes a receive blob of any version the site
// has ever written.
func decodeReceiveBlob(
	blob tapreorg.VersionedBlob) (chainhash.Hash, error) {

	var txid chainhash.Hash
	if blob.Version != receiveBlobVersion {
		return txid, fmt.Errorf("unknown receive blob version %d",
			blob.Version)
	}
	if len(blob.Data) != 32 {
		return txid, fmt.Errorf("receive blob has %d bytes",
			len(blob.Data))
	}
	copy(txid[:], blob.Data)

	return txid, nil
}

// receiveSite is the receive side's re-org watcher site: the
// custodian stakes imported proofs, materialized assets and completed
// address events on the sender's anchor transaction, and these
// handlers converge that state to whatever the chain answers.
type receiveSite struct {
	custodian *Custodian
}

// ID returns the site's stable identifier.
func (s *receiveSite) ID() tapreorg.SiteID {
	return ReceiveSiteID
}

// EvaluateCandidate judges a spend of the received transfer's inputs:
// only the exact anchor transaction the proofs attest satisfies the
// anchoring. A replacement published by the sender is foreign here —
// the receiver cannot validate it without a new proof, which arrives
// as a fresh receive with its own anchoring while this one abandons.
func (s *receiveSite) EvaluateCandidate(match tapreorg.VersionedBlob,
	spendingTx *wire.MsgTx) (tapreorg.Verdict, error) {

	anchorTxid, err := decodeReceiveBlob(match)
	if err != nil {
		return 0, err
	}

	if spendingTx.TxHash() == anchorTxid {
		return tapreorg.VerdictSatisfies, nil
	}

	return tapreorg.VerdictForeign, nil
}

// receiveWitnessContext extracts the given phase's witness candidate
// with its block enrichment.
func receiveWitnessContext(anchoring *tapreorg.Anchoring,
	phase tapreorg.Phase) (*tapreorg.CandidateSpend, error) {

	var witness tapreorg.Witness
	switch p := phase.(type) {
	case tapreorg.Witnessed:
		witness = p.W

	case tapreorg.Buried:
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

		enriched := *candidate
		enriched.W = witness

		return &enriched, nil
	}

	return nil, fmt.Errorf("witness %v not among candidates",
		witness.TxHash())
}

// reconfirm converges received state to the current witness.
func (s *receiveSite) reconfirm(ctx context.Context,
	tx tapreorg.RegistryTx, anchoring *tapreorg.Anchoring) error {

	anchorTxid, err := decodeReceiveBlob(anchoring.Payload)
	if err != nil {
		return err
	}

	witness, err := receiveWitnessContext(anchoring, anchoring.Phase)
	if err != nil {
		return err
	}

	return s.custodian.cfg.AnchoringLog.ApplyReceiveReconfirm(
		ctx, tx.Queries(), anchorTxid, witness.W.BlockHash(),
		witness.W.Height(), witness.W.TxIndex(),
		*witness.BlockHeader, *witness.MerkleProof,
	)
}

// OnWitnessed converges the receive to a confirmed anchor, refreshed
// block context included.
func (s *receiveSite) OnWitnessed(ctx context.Context,
	tx tapreorg.RegistryTx, anchoring *tapreorg.Anchoring) error {

	return s.reconfirm(ctx, tx, anchoring)
}

// OnUnwitnessed withdraws the recorded confirmation: soft downgrade
// only.
func (s *receiveSite) OnUnwitnessed(ctx context.Context,
	tx tapreorg.RegistryTx, anchoring *tapreorg.Anchoring) error {

	anchorTxid, err := decodeReceiveBlob(anchoring.Payload)
	if err != nil {
		return err
	}

	return s.custodian.cfg.AnchoringLog.ApplyReceiveUnconfirm(
		ctx, tx.Queries(), anchorTxid,
	)
}

// OnConflicted takes the same soft action as OnUnwitnessed: the
// foreign spend can itself re-org out.
func (s *receiveSite) OnConflicted(ctx context.Context,
	tx tapreorg.RegistryTx, anchoring *tapreorg.Anchoring) error {

	anchorTxid, err := decodeReceiveBlob(anchoring.Payload)
	if err != nil {
		return err
	}

	return s.custodian.cfg.AnchoringLog.ApplyReceiveUnconfirm(
		ctx, tx.Queries(), anchorTxid,
	)
}

// OnBuried converges to act-level confirmation. The receive side
// emits nothing across trust boundaries, so burial is simply the
// final convergent confirmation.
func (s *receiveSite) OnBuried(ctx context.Context,
	tx tapreorg.RegistryTx, anchoring *tapreorg.Anchoring) error {

	return s.reconfirm(ctx, tx, anchoring)
}

// OnAbandoned compensates: the sender's anchor transaction was
// decided against with act-level finality, so the received assets
// never materialized on the surviving chain.
func (s *receiveSite) OnAbandoned(ctx context.Context,
	tx tapreorg.RegistryTx, anchoring *tapreorg.Anchoring) error {

	anchorTxid, err := decodeReceiveBlob(anchoring.Payload)
	if err != nil {
		return err
	}

	return s.custodian.cfg.AnchoringLog.ApplyReceiveAbandonment(
		ctx, tx.Queries(), anchorTxid,
		int16(address.StatusTransactionDetected),
	)
}

// A compile-time assertion that the receive site satisfies the site
// contract.
var _ tapreorg.Site = (*receiveSite)(nil)

// AnchoringSite returns the custodian's site implementation, for
// registration with the re-org watcher.
func (c *Custodian) AnchoringSite() tapreorg.Site {
	return &receiveSite{custodian: c}
}

// RegisterReceiveAnchoring stakes a received proof file's state on
// its tip anchor transaction. The trigger set is derived from the
// file itself: the tip proof's asset-bearing previous outpoints, with
// their scripts recovered from the preceding proofs in the file (and
// from the tips of any additional-input files). Registration is
// idempotent per anchor transaction — receives sharing the anchor
// share the anchoring.
//
// Files whose trigger set cannot be derived (a single-proof genesis
// file has no asset-bearing inputs) seed the anchor tx directly as
// the anchoring's candidate spend instead of watching for a
// witnessing spender — the tx is already witnessed by its own
// confirmation, and the watcher's conf subscription on it certifies
// act crossing and detects re-org-out.
func (c *Custodian) RegisterReceiveAnchoring(ctx context.Context,
	file *proof.File) error {

	numProofs := file.NumProofs()
	if numProofs == 0 {
		return fmt.Errorf("empty proof file")
	}

	tip, err := file.ProofAt(uint32(numProofs - 1))
	if err != nil {
		return fmt.Errorf("unable to read tip proof: %w", err)
	}
	anchorTxid := tip.AnchorTx.TxHash()

	// One anchoring per anchor transaction: if a previous receive
	// (or another output of the same send) already registered it,
	// nothing to do.
	matchKey := anchorTxid.CloneBytes()
	existing, err := c.cfg.AnchoringWatcher.LookupByMatchKey(
		ctx, ReceiveSiteID, matchKey,
	)
	if err != nil {
		return fmt.Errorf("unable to look up receive anchoring: "+
			"%w", err)
	}
	if existing != nil {
		return nil
	}

	// A file with derivable asset-bearing triggers registers the
	// ordinary way: spend subscriptions on the trigger set observe
	// the anchor tx confirming (as the witnessing spender) and any
	// foreign spender as a foreclosure. A file without them (a
	// single-proof genesis receive) has no prior outpoint to watch,
	// so it seeds its already-known anchor tx as the anchoring's
	// candidate spend: the watcher's conf subscription on that tx
	// certifies act crossing and detects re-org-out directly.
	blob := encodeReceiveBlob(anchorTxid)
	spec := tapreorg.RegistrationSpec{
		Site:      ReceiveSiteID,
		MatchData: blob,
		Payload:   blob,
		MatchKey:  matchKey,
		Threshold: c.cfg.AnchoringThreshold,
	}

	points, err := receiveTriggerPoints(file, tip)
	switch {
	case errors.Is(err, ErrNoTriggers):
		// The seed path needs a confirmed anchor tx: its block
		// context is what the watcher's conf subscription
		// certifies against. A tip without block context
		// (a stub, or a proof imported before confirmation) is
		// not stakeable here; return ErrUnwatchable so callers
		// see the outcome legibly rather than mistaking it for
		// successful registration.
		if tip.BlockHeight == 0 {
			return fmt.Errorf("%w: genesis-shape file with no "+
				"block context (anchor_txid=%v)",
				ErrUnwatchable, anchorTxid)
		}

		seed, seedErr := genesisSeedCandidate(tip)
		if seedErr != nil {
			return fmt.Errorf("unable to build genesis seed: "+
				"%w", seedErr)
		}
		spec.SeedCandidate = &seed

	case err != nil:
		return err

	default:
		triggers, err := tapreorg.NewTriggerSet(points)
		if err != nil {
			return fmt.Errorf("unable to build trigger set: %w",
				err)
		}
		spec.Triggers = triggers
	}

	_, err = c.cfg.AnchoringWatcher.Register(
		ctx, spec,
		// The receiver's speculative writes (the proof import
		// and event completion) happen through the archive
		// pipeline before registration; the custodian's own
		// restart recovery re-runs that pipeline and lands back
		// here, so a crash between the two self-heals.
		nil,
	)
	if err != nil {
		return fmt.Errorf("unable to register receive "+
			"anchoring: %w", err)
	}

	return nil
}

// genesisSeedCandidate builds a fully-enriched candidate spend from a
// genesis-shaped proof file's tip. All the required data lives in the
// proof: the anchor tx, its confirmation block header + height, and
// its merkle proof (which also encodes the tx's index within the
// block). The candidate is on-chain; act certification and re-org
// sensing follow through the watcher's conf subscription on the
// anchor tx.
func genesisSeedCandidate(
	tip *proof.Proof) (tapreorg.CandidateSpend, error) {

	blockHash := tip.BlockHeader.BlockHash()
	txIndex := tip.TxMerkleProof.TxIndex()

	witness, err := tapreorg.NewWitness(
		&tip.AnchorTx, blockHash, tip.BlockHeight, txIndex,
	)
	if err != nil {
		return tapreorg.CandidateSpend{}, fmt.Errorf("unable to "+
			"build witness: %w", err)
	}

	header := tip.BlockHeader
	merkle := tip.TxMerkleProof

	return tapreorg.CandidateSpend{
		W:            witness,
		Verdict:      tapreorg.VerdictSatisfies,
		OnChain:      true,
		BlockHeader:  &header,
		MerkleProof:  &merkle,
		ActCertified: false,
	}, nil
}

// ErrNoTriggers marks a proof file from which no asset-bearing
// trigger set can be derived (a single-proof genesis file has no
// asset-bearing inputs). It is an internal signal from
// receiveTriggerPoints to RegisterReceiveAnchoring, which handles it
// by seeding the anchor tx as the anchoring's candidate spend rather
// than watching for a witnessing spender.
var ErrNoTriggers = fmt.Errorf("no derivable trigger outpoints")

// ErrUnwatchable is returned by RegisterReceiveAnchoring when the
// proof file's tip carries no chain context we can stake on — the
// canonical case is a single-proof genesis file imported before its
// anchor transaction confirmed. The registration is a non-event, not
// a failure: callers typically log and continue, but the typed
// signal lets them distinguish "watched" from "un-watched" outcomes
// without conflating both with a nil return.
var ErrUnwatchable = fmt.Errorf("proof file is not watchable")

// receiveTriggerPoints derives the anchoring's trigger set from a
// proof file: the tip transition's previous asset outpoint (script
// recovered from the preceding proof) plus the tips of any
// additional-input files.
func receiveTriggerPoints(file *proof.File,
	tip *proof.Proof) ([]tapreorg.TriggerOutPoint, error) {

	numProofs := file.NumProofs()
	if numProofs < 2 {
		return nil, ErrNoTriggers
	}

	prev, err := file.ProofAt(uint32(numProofs - 2))
	if err != nil {
		return nil, fmt.Errorf("unable to read preceding proof: %w",
			err)
	}
	prevOut := tip.PrevOut
	if int(prevOut.Index) >= len(prev.AnchorTx.TxOut) {
		return nil, fmt.Errorf("previous outpoint index %d out of "+
			"range", prevOut.Index)
	}

	points := []tapreorg.TriggerOutPoint{{
		OutPoint:   prevOut,
		PkScript:   prev.AnchorTx.TxOut[prevOut.Index].PkScript,
		HeightHint: prev.BlockHeight,
	}}

	for idx := range tip.AdditionalInputs {
		inputFile := &tip.AdditionalInputs[idx]
		numInput := inputFile.NumProofs()
		if numInput == 0 {
			continue
		}
		inputTip, err := inputFile.ProofAt(uint32(numInput - 1))
		if err != nil {
			return nil, fmt.Errorf("unable to read additional "+
				"input tip: %w", err)
		}

		op := inputTip.OutPoint()
		outputIndex := inputTip.InclusionProof.OutputIndex
		if int(outputIndex) >= len(inputTip.AnchorTx.TxOut) {
			return nil, fmt.Errorf("inclusion output index %d "+
				"out of range", outputIndex)
		}

		points = append(points, tapreorg.TriggerOutPoint{
			OutPoint: op,
			PkScript: inputTip.AnchorTx.
				TxOut[outputIndex].PkScript,
			HeightHint: inputTip.BlockHeight,
		})
	}

	return points, nil
}
