package supplycommit

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/tapnode"
	"github.com/lightninglabs/taproot-assets/tapreorg"
)

const (
	// SupplySiteID identifies the supply-commit state machine as a
	// re-org watcher site.
	SupplySiteID tapreorg.SiteID = "supplycommit.committer"

	// CommitFinalizeEffectKind is the outbox effect kind under which
	// a buried supply commitment's finalize event is dispatched into
	// the state machine. Finalization persists the new commitment
	// root and pushes it to remote universes — an irrevocable
	// assertion to receivers that re-check nothing — so it is
	// act-gated: the machine sits in its broadcast state until the
	// commit transaction is buried.
	CommitFinalizeEffectKind tapreorg.EffectKind = "supplycommit." +
		"finalize"

	// supplyBlobVersion versions the supply site's anchoring blobs.
	supplyBlobVersion = 1
)

// supplyBlob is the supply site's anchoring blob: the commit
// transaction plus the asset group it commits for, so the finalize
// event can be routed to the right state machine.
type supplyBlob struct {
	// CommitTxid is the broadcast commitment transaction.
	CommitTxid chainhash.Hash

	// GroupKey is the asset group's serialized key.
	GroupKey [33]byte
}

// encodeSupplyBlob encodes a supply blob.
func encodeSupplyBlob(blob supplyBlob) tapreorg.VersionedBlob {
	data := make([]byte, 0, 32+33)
	data = append(data, blob.CommitTxid[:]...)
	data = append(data, blob.GroupKey[:]...)

	return tapreorg.VersionedBlob{
		Version: supplyBlobVersion,
		Data:    data,
	}
}

// decodeSupplyBlob decodes a supply blob of any version the site has
// ever written.
func decodeSupplyBlob(blob tapreorg.VersionedBlob) (supplyBlob, error) {
	var out supplyBlob
	if blob.Version != supplyBlobVersion {
		return out, fmt.Errorf("unknown supply blob version %d",
			blob.Version)
	}
	if len(blob.Data) != 32+33 {
		return out, fmt.Errorf("supply blob has %d bytes",
			len(blob.Data))
	}
	copy(out.CommitTxid[:], blob.Data[:32])
	copy(out.GroupKey[:], blob.Data[32:])

	return out, nil
}

// SupplySite is the supply-commit state machine's re-org watcher
// site. It is the purest defer-until-buried site: nothing is
// persisted or emitted before burial, so the potency-tier handlers
// have nothing to converge, burial enqueues the finalize event, and
// abandonment has nothing to compensate — it is surfaced loudly for
// the operator, since it means the commitment's own inputs (prior
// commitment or pre-commitments, which only this daemon controls)
// were claimed by a buried conflicting transaction.
type SupplySite struct{}

// ID returns the site's stable identifier.
func (s *SupplySite) ID() tapreorg.SiteID {
	return SupplySiteID
}

// EvaluateCandidate judges a spend of the commitment's inputs:
// exactly the broadcast commit transaction satisfies.
func (s *SupplySite) EvaluateCandidate(match tapreorg.VersionedBlob,
	spendingTx *wire.MsgTx) (tapreorg.Verdict, error) {

	blob, err := decodeSupplyBlob(match)
	if err != nil {
		return 0, err
	}

	if spendingTx.TxHash() == blob.CommitTxid {
		return tapreorg.VerdictSatisfies, nil
	}

	return tapreorg.VerdictForeign, nil
}

// OnWitnessed is a no-op: nothing is persisted before burial.
func (s *SupplySite) OnWitnessed(_ context.Context, _ tapreorg.RegistryTx,
	anchoring *tapreorg.Anchoring) error {

	log.Debugf("Supply commit anchoring %d witnessed", anchoring.ID)

	return nil
}

// OnUnwitnessed is a no-op: nothing to downgrade.
func (s *SupplySite) OnUnwitnessed(_ context.Context, _ tapreorg.RegistryTx,
	anchoring *tapreorg.Anchoring) error {

	log.Debugf("Supply commit anchoring %d unwitnessed", anchoring.ID)

	return nil
}

// OnConflicted is a no-op at the potency tier.
func (s *SupplySite) OnConflicted(_ context.Context, _ tapreorg.RegistryTx,
	anchoring *tapreorg.Anchoring) error {

	log.Warnf("Supply commit anchoring %d conflicted: a foreign "+
		"transaction spends its inputs", anchoring.ID)

	return nil
}

// OnBuried enqueues the finalize event: the commit transaction is
// act-confirmed, so the machine may persist the new root and push it
// to remote universes.
func (s *SupplySite) OnBuried(ctx context.Context, tx tapreorg.RegistryTx,
	anchoring *tapreorg.Anchoring) error {

	return tx.EnqueueEffect(ctx, tapreorg.OutboxEffect{
		Kind:      CommitFinalizeEffectKind,
		Anchoring: fn.Some(anchoring.ID),
		Payload:   anchoring.Payload,
	})
}

// OnAbandoned surfaces the loss: nothing was persisted or emitted, so
// there is nothing to compensate, but the machine is now stalled in
// its broadcast state on a transaction the chain has decided against.
// That can only happen when this daemon's own inputs were spent out
// from under it, which no automated compensation can honestly
// resolve; the anchoring registry documents the condition for the
// operator.
func (s *SupplySite) OnAbandoned(_ context.Context, _ tapreorg.RegistryTx,
	anchoring *tapreorg.Anchoring) error {

	log.Errorf("Supply commit anchoring %d ABANDONED: the commitment "+
		"transaction's inputs were claimed by a buried conflicting "+
		"transaction; the supply-commit state machine for this "+
		"group requires operator attention", anchoring.ID)

	return nil
}

// A compile-time assertion that the supply site satisfies the site
// contract.
var _ tapreorg.Site = (*SupplySite)(nil)

// registerCommitAnchoring stakes the supply transition on its commit
// transaction: idempotent per commit transaction. The trigger set is
// the transaction's inputs — the prior commitment and the spent
// pre-commitments, whose creating transactions the transition carries
// — an essential identity, since any future commitment must spend
// them.
func registerCommitAnchoring(ctx context.Context, env *Environment,
	transition *SupplyStateTransition) error {

	commitTx := transition.NewCommitment.Txn
	commitTxid := commitTx.TxHash()

	groupKey, err := env.AssetSpec.UnwrapGroupKeyOrErr()
	if err != nil {
		return fmt.Errorf("unable to unwrap group key: %w", err)
	}
	var rawGroupKey [33]byte
	copy(rawGroupKey[:], groupKey.SerializeCompressed())

	existing, err := env.AnchoringWatcher.Anchorings(ctx, SupplySiteID)
	if err != nil {
		return fmt.Errorf("unable to list anchorings: %w", err)
	}
	for _, anchoring := range existing {
		blob, err := decodeSupplyBlob(anchoring.Payload)
		if err != nil {
			continue
		}
		if blob.CommitTxid == commitTxid {
			return nil
		}
	}

	// Input scripts come from the transition itself: the prior
	// commitment's output and the pre-commitment outputs.
	scripts := make(map[wire.OutPoint][]byte)
	transition.OldCommitment.WhenSome(func(old RootCommitment) {
		if old.Txn == nil ||
			int(old.TxOutIdx) >= len(old.Txn.TxOut) {

			return
		}
		op := wire.OutPoint{
			Hash:  old.Txn.TxHash(),
			Index: old.TxOutIdx,
		}
		scripts[op] = old.Txn.TxOut[old.TxOutIdx].PkScript
	})
	for idx := range transition.UnspentPreCommits {
		preCommit := transition.UnspentPreCommits[idx]
		if preCommit.MintingTxn == nil ||
			int(preCommit.OutIdx) >= len(
				preCommit.MintingTxn.TxOut,
			) {

			continue
		}
		op := wire.OutPoint{
			Hash:  preCommit.MintingTxn.TxHash(),
			Index: preCommit.OutIdx,
		}
		scripts[op] = preCommit.MintingTxn.TxOut[preCommit.OutIdx].
			PkScript
	}

	points := make([]tapreorg.TriggerOutPoint, 0, len(commitTx.TxIn))
	for _, txIn := range commitTx.TxIn {
		points = append(points, tapreorg.TriggerOutPoint{
			OutPoint: txIn.PreviousOutPoint,
			PkScript: scripts[txIn.PreviousOutPoint],
		})
	}
	triggers, err := tapreorg.NewTriggerSet(points)
	if err != nil {
		return fmt.Errorf("unable to build trigger set: %w", err)
	}

	blob := encodeSupplyBlob(supplyBlob{
		CommitTxid: commitTxid,
		GroupKey:   rawGroupKey,
	})

	_, err = env.AnchoringWatcher.Register(
		ctx, tapreorg.RegistrationSpec{
			Site:      SupplySiteID,
			Triggers:  triggers,
			MatchData: blob,
			Payload:   blob,
			Threshold: env.AnchoringThreshold,
		}, nil,
	)
	if err != nil {
		return fmt.Errorf("unable to register commit anchoring: %w",
			err)
	}

	return nil
}

// DispatchCommitFinalize is the outbox dispatch handler for a buried
// commitment: it reconstructs the confirmation event from the
// anchoring's witness (fetching the full block, which the machine's
// finalize path needs for its merkle proof) and sends it into the
// group's state machine. Idempotent — a machine past its broadcast
// state ignores stray confirmation events.
func DispatchCommitFinalize(ctx context.Context,
	watcher *tapreorg.Watcher, chain tapnode.ChainBridge,
	manager *Manager, anchoringID fn.Option[tapreorg.AnchoringID],
	payload tapreorg.VersionedBlob) error {

	blob, err := decodeSupplyBlob(payload)
	if err != nil {
		return err
	}

	id, err := anchoringID.UnwrapOrErr(fmt.Errorf("finalize effect "+
		"lacks an anchoring: %v", blob.CommitTxid))
	if err != nil {
		return err
	}

	anchoring, err := watcher.Anchoring(ctx, id)
	if err != nil {
		return err
	}

	var witness *tapreorg.Witness
	switch phase := anchoring.Phase.(type) {
	case tapreorg.Buried:
		witness = &phase.W

	case tapreorg.Witnessed:
		witness = &phase.W

	default:
		return fmt.Errorf("anchoring %d has no witness in phase %v",
			id, anchoring.Phase)
	}

	block, err := chain.GetBlock(ctx, witness.BlockHash())
	if err != nil {
		return fmt.Errorf("unable to fetch witness block: %w", err)
	}

	groupKey, err := btcec.ParsePubKey(blob.GroupKey[:])
	if err != nil {
		return fmt.Errorf("unable to parse group key: %w", err)
	}

	return manager.SendEvent(
		ctx, asset.NewSpecifierFromGroupKey(*groupKey), &ConfEvent{
			Tx:          witness.Tx(),
			TxIndex:     witness.TxIndex(),
			BlockHeight: witness.Height(),
			Block:       block,
		},
	)
}
