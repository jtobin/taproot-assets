package tapgarden

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapnode"
	"github.com/lightninglabs/taproot-assets/tapreorg"
	"github.com/lightningnetwork/lnd/chainntnfs"
)

const (
	// MintSiteID identifies the minting side (the cultivator) as a
	// re-org watcher site.
	MintSiteID tapreorg.SiteID = "tapgarden.minter"

	// MintPublishEffectKind is the outbox effect kind under which a
	// buried batch's universe publication and supply-commit events
	// are dispatched. Both are irrevocable assertions to receivers
	// that re-check nothing, so they are act-gated: they fire at
	// burial depth and only there. This deliberately delays new
	// issuance's universe availability by the mint's threshold;
	// operators who want faster propagation lower the threshold
	// knowingly.
	MintPublishEffectKind tapreorg.EffectKind = "tapgarden.mint-publish"

	// mintBlobVersion versions the mint site's anchoring blobs.
	mintBlobVersion = 1
)

// MintAnchoringLog is the transaction-scoped persistence surface the
// mint site drives from its handlers, implemented by the asset store.
// (Re)confirmation and the potency-tier unconfirm reuse the receive
// side's bodies: minted state has the same shape as received state.
type MintAnchoringLog interface {
	// ApplyReceiveReconfirm converges anchored state to a
	// (re)confirmed transaction.
	ApplyReceiveReconfirm(ctx context.Context, q *sqlc.Queries,
		anchorTxid chainhash.Hash, blockHash chainhash.Hash,
		blockHeight, txIndex uint32, header wire.BlockHeader,
		merkle proof.TxMerkleProof) error

	// ApplyReceiveUnconfirm withdraws the recorded confirmation.
	ApplyReceiveUnconfirm(ctx context.Context, q *sqlc.Queries,
		anchorTxid chainhash.Hash) error

	// ApplyMintAbandonment compensates an abandoned batch.
	ApplyMintAbandonment(ctx context.Context, q *sqlc.Queries,
		genesisTxid chainhash.Hash, rawBatchKey []byte) error
}

// mintBlob is the mint site's anchoring blob: the batch key plus the
// genesis transaction it broadcast.
type mintBlob struct {
	// RawBatchKey is the batch's serialized public key.
	RawBatchKey [33]byte

	// GenesisTxid is the broadcast genesis transaction.
	GenesisTxid chainhash.Hash
}

// encodeMintBlob encodes a mint blob.
func encodeMintBlob(blob mintBlob) tapreorg.VersionedBlob {
	data := make([]byte, 0, 33+32)
	data = append(data, blob.RawBatchKey[:]...)
	data = append(data, blob.GenesisTxid[:]...)

	return tapreorg.VersionedBlob{
		Version: mintBlobVersion,
		Data:    data,
	}
}

// decodeMintBlob decodes a mint blob of any version the site has ever
// written.
func decodeMintBlob(blob tapreorg.VersionedBlob) (mintBlob, error) {
	var out mintBlob
	if blob.Version != mintBlobVersion {
		return out, fmt.Errorf("unknown mint blob version %d",
			blob.Version)
	}
	if len(blob.Data) != 33+32 {
		return out, fmt.Errorf("mint blob has %d bytes",
			len(blob.Data))
	}
	copy(out.RawBatchKey[:], blob.Data[:33])
	copy(out.GenesisTxid[:], blob.Data[33:])

	return out, nil
}

// mintSite is the minting side's re-org watcher site: a batch stakes
// its assets on the genesis transaction confirming, and these
// handlers converge that state to whatever the chain answers.
//
// The mint's trigger-set identity is conventional, not essential: a
// genesis transaction's inputs are fungible wallet UTXOs, so the
// identity holds only as long as the cultivator itself controls
// replacement. The cultivator never re-funds a broadcast batch today;
// if it ever does, it must withdraw this anchoring and register a new
// one, because a re-funded replacement can have a disjoint input set
// the watcher would never see.
type mintSite struct {
	planter *ChainPlanter
}

// ID returns the site's stable identifier.
func (s *mintSite) ID() tapreorg.SiteID {
	return MintSiteID
}

// EvaluateCandidate judges a spend of the genesis transaction's
// funding inputs: exactly the broadcast transaction satisfies; any
// other spender (an external wallet conflict) is foreign.
func (s *mintSite) EvaluateCandidate(match tapreorg.VersionedBlob,
	spendingTx *wire.MsgTx) (tapreorg.Verdict, error) {

	blob, err := decodeMintBlob(match)
	if err != nil {
		return 0, err
	}

	if spendingTx.TxHash() == blob.GenesisTxid {
		return tapreorg.VerdictSatisfies, nil
	}

	return tapreorg.VerdictForeign, nil
}

// reconfirm converges minted state to the current witness.
func (s *mintSite) reconfirm(ctx context.Context, tx tapreorg.RegistryTx,
	anchoring *tapreorg.Anchoring) error {

	blob, err := decodeMintBlob(anchoring.Payload)
	if err != nil {
		return err
	}

	witness, err := tapreorg.WitnessContext(anchoring, anchoring.Phase)
	if err != nil {
		return err
	}

	return s.planter.cfg.MintAnchoringLog.ApplyReceiveReconfirm(
		ctx, tx.Queries(), blob.GenesisTxid, witness.W.BlockHash(),
		witness.W.Height(), witness.W.TxIndex(),
		*witness.BlockHeader, *witness.MerkleProof,
	)
}

// OnWitnessed converges the batch to a confirmed genesis, refreshed
// block context included. It runs convergently alongside the
// cultivator's own confirmation branch: both derive the same values
// from the same witness.
func (s *mintSite) OnWitnessed(ctx context.Context, tx tapreorg.RegistryTx,
	anchoring *tapreorg.Anchoring) error {

	return s.reconfirm(ctx, tx, anchoring)
}

// OnUnwitnessed withdraws the recorded confirmation: soft downgrade
// only.
func (s *mintSite) OnUnwitnessed(ctx context.Context,
	tx tapreorg.RegistryTx, anchoring *tapreorg.Anchoring) error {

	blob, err := decodeMintBlob(anchoring.Payload)
	if err != nil {
		return err
	}

	return s.planter.cfg.MintAnchoringLog.ApplyReceiveUnconfirm(
		ctx, tx.Queries(), blob.GenesisTxid,
	)
}

// OnConflicted takes the same soft action as OnUnwitnessed.
func (s *mintSite) OnConflicted(ctx context.Context,
	tx tapreorg.RegistryTx, anchoring *tapreorg.Anchoring) error {

	blob, err := decodeMintBlob(anchoring.Payload)
	if err != nil {
		return err
	}

	return s.planter.cfg.MintAnchoringLog.ApplyReceiveUnconfirm(
		ctx, tx.Queries(), blob.GenesisTxid,
	)
}

// OnBuried converges to act-level confirmation and enqueues the
// batch's act-gated external emissions: universe publication and
// supply-commit events fire at burial, and only at burial.
func (s *mintSite) OnBuried(ctx context.Context, tx tapreorg.RegistryTx,
	anchoring *tapreorg.Anchoring) error {

	if err := s.reconfirm(ctx, tx, anchoring); err != nil {
		return err
	}

	return tx.EnqueueEffect(ctx, tapreorg.OutboxEffect{
		Kind:      MintPublishEffectKind,
		Anchoring: fn.Some(anchoring.ID),
		Payload:   anchoring.Payload,
	})
}

// OnAbandoned compensates: the chain decided against the genesis
// transaction with act-level finality, so the batch's assets never
// came to be. Nothing was published externally — publication is
// act-gated — so compensation is purely local.
func (s *mintSite) OnAbandoned(ctx context.Context, tx tapreorg.RegistryTx,
	anchoring *tapreorg.Anchoring) error {

	blob, err := decodeMintBlob(anchoring.Payload)
	if err != nil {
		return err
	}

	return s.planter.cfg.MintAnchoringLog.ApplyMintAbandonment(
		ctx, tx.Queries(), blob.GenesisTxid, blob.RawBatchKey[:],
	)
}

// A compile-time assertion that the mint site satisfies the site
// contract.
var _ tapreorg.Site = (*mintSite)(nil)

// AnchoringSite returns the planter's mint site implementation, for
// registration with the re-org watcher.
func (c *ChainPlanter) AnchoringSite() tapreorg.Site {
	return &mintSite{planter: c}
}

// DispatchMintPublish is the outbox dispatch handler for a buried
// batch's external emissions: it reloads the batch and its minted
// proofs from the database and runs the universe publication and the
// augmenter's confirmation-side obligations. Both are idempotent (the
// publisher rides upserts; the augmenter's events dedup by content
// hash), so redelivery is harmless.
func (c *ChainPlanter) DispatchMintPublish(ctx context.Context,
	_ fn.Option[tapreorg.AnchoringID],
	payload tapreorg.VersionedBlob) error {

	blob, err := decodeMintBlob(payload)
	if err != nil {
		return err
	}

	batchKey, err := btcec.ParsePubKey(blob.RawBatchKey[:])
	if err != nil {
		return fmt.Errorf("unable to parse batch key: %w", err)
	}

	batch, err := c.cfg.BatchStore.FetchMintingBatch(ctx, batchKey)
	if err != nil {
		return fmt.Errorf("unable to fetch batch: %w", err)
	}

	// A finalized batch stores its assets in the proof archive rather
	// than the sprout tables — the dispatch may run after the
	// cultivator has already finalized the batch, so rebuild the
	// commitment from the archived issuance proofs in that case.
	if batch.RootAssetCommitment == nil &&
		batch.State() == BatchStateFinalized {

		batch, err = fetchFinalizedBatch(
			ctx, c.cfg.MintingRefs, c.cfg.ProofFiles, batch,
		)
		if err != nil {
			return fmt.Errorf("unable to fetch finalized "+
				"batch: %w", err)
		}
	}
	if batch.RootAssetCommitment == nil {
		return fmt.Errorf("batch %x has no commitment",
			blob.RawBatchKey)
	}

	committedAssets := batch.RootAssetCommitment.CommittedAssets()

	// Read the minted proofs from the archive that includes the
	// database store: the re-org watcher's re-confirmation handlers
	// re-stamp the stored proofs there, while the flat-file mirror
	// keeps the block context the confirmation originally wrote.
	proofReader := c.cfg.ProofArchive
	if proofReader == nil {
		proofReader = c.cfg.ProofFiles
	}

	// The minted proofs, as the confirmation stored them.
	mintingProofs := make(
		map[asset.SerializedKey]*proof.Proof, len(committedAssets),
	)
	for idx := range committedAssets {
		mintedAsset := committedAssets[idx]
		scriptKey := asset.ToSerialized(
			mintedAsset.ScriptKey.PubKey,
		)

		blobBytes, err := proofReader.FetchProof(
			ctx, proof.Locator{
				AssetID: fn.Ptr(mintedAsset.ID()),
				ScriptKey: *mintedAsset.ScriptKey.
					PubKey,
			},
		)
		if err != nil {
			return fmt.Errorf("unable to fetch minted proof: "+
				"%w", err)
		}

		file := &proof.File{}
		if err := file.Decode(bytes.NewReader(blobBytes)); err != nil {
			return fmt.Errorf("unable to decode minted proof: "+
				"%w", err)
		}
		tip, err := file.ProofAt(uint32(file.NumProofs() - 1))
		if err != nil {
			return fmt.Errorf("unable to read minted proof "+
				"tip: %w", err)
		}

		mintingProofs[scriptKey] = tip
	}

	// Group anchors precede reissuances, as the universe requires.
	groupAnchorVerifier := tapnode.GenGroupAnchorVerifier(
		ctx, c.cfg.MintingRefs,
	)
	anchorAssets, nonAnchorAssets, err := SortAssets(
		committedAssets, groupAnchorVerifier,
	)
	if err != nil {
		return fmt.Errorf("could not sort assets: %w", err)
	}

	// The augmenter's obligations run before the universe
	// publication: the publication is the externally observable
	// emission, so its visibility certifies that every act-gated
	// consequence of this batch — the supply-commit events included —
	// has already landed.
	augmenter := c.cfg.GenesisTxAugmenter
	if augmenter == nil {
		augmenter = NoOpAugmenter{}
	}
	err = augmenter.OnBatchConfirmed(
		ctx, batch, anchorAssets, nonAnchorAssets, mintingProofs,
	)
	if err != nil {
		return fmt.Errorf("augmenter OnBatchConfirmed: %w", err)
	}

	if c.cfg.MintProofPublisher != nil {
		publishAssets := make(
			[]*asset.Asset, 0,
			len(anchorAssets)+len(nonAnchorAssets),
		)
		publishAssets = append(publishAssets, anchorAssets...)
		publishAssets = append(publishAssets, nonAnchorAssets...)

		anchorIdx := batch.GenesisPacket.AssetAnchorOutIdx
		err = c.cfg.MintProofPublisher.PublishMintBatch(
			ctx, MintBatchPublishParams{
				Assets:       publishAssets,
				Proofs:       mintingProofs,
				MintTxHash:   blob.GenesisTxid,
				AnchorOutIdx: anchorIdx,
			},
		)
		if err != nil {
			return fmt.Errorf("unable to publish minted "+
				"batch: %w", err)
		}
	}

	return nil
}

// registerMintAnchoring stakes the batch on its genesis transaction
// confirming: idempotent per genesis transaction. The trigger set is
// the genesis transaction's funding inputs, with scripts from the
// funded PSBT.
//
// Identity constraint. The funding inputs are conventional identity,
// not essential: they identify THIS batch's signing choice, not any
// batch signing choice for the same seedlings. If the batch is ever
// replaced or refunded with different inputs (RBF or manual
// re-signing on abandon-and-retry), the anchoring must be Withdrawn
// and a fresh registration issued on the replacement's inputs —
// otherwise the original anchoring watches inputs that will never be
// spent while the actual confirming transaction goes unwitnessed. The
// cultivator does not currently exercise this path (batches are
// abandon-and-recreate, and the fresh batch registers its own
// anchoring), but any future RBF or same-batch re-fund must call
// Withdraw + register anew.
func (b *Cultivator) registerMintAnchoring(ctx context.Context,
	signedTx *wire.MsgTx) error {

	genesisTxid := signedTx.TxHash()

	matchKey := genesisTxid.CloneBytes()
	existing, err := b.cfg.AnchoringWatcher.LookupByMatchKey(
		ctx, MintSiteID, matchKey,
	)
	if err != nil {
		return fmt.Errorf("unable to look up mint anchoring: %w",
			err)
	}
	if existing != nil {
		return nil
	}

	// Input scripts come from the funded PSBT.
	pkt := b.cfg.Batch.GenesisPacket.Pkt
	scripts := make(map[wire.OutPoint][]byte, len(pkt.Inputs))
	for idx := range pkt.Inputs {
		if idx >= len(pkt.UnsignedTx.TxIn) {
			break
		}
		if pkt.Inputs[idx].WitnessUtxo == nil {
			continue
		}
		op := pkt.UnsignedTx.TxIn[idx].PreviousOutPoint
		scripts[op] = pkt.Inputs[idx].WitnessUtxo.PkScript
	}

	points := make([]tapreorg.TriggerOutPoint, 0, len(signedTx.TxIn))
	for _, txIn := range signedTx.TxIn {
		points = append(points, tapreorg.TriggerOutPoint{
			OutPoint:   txIn.PreviousOutPoint,
			PkScript:   scripts[txIn.PreviousOutPoint],
			HeightHint: b.cfg.Batch.HeightHint,
		})
	}
	triggers, err := tapreorg.NewTriggerSet(points)
	if err != nil {
		return fmt.Errorf("unable to build trigger set: %w", err)
	}

	var rawKey [33]byte
	copy(rawKey[:], b.cfg.Batch.BatchKey.PubKey.SerializeCompressed())
	blob := encodeMintBlob(mintBlob{
		RawBatchKey: rawKey,
		GenesisTxid: genesisTxid,
	})

	// The batch's speculative writes happened through the batch
	// store before broadcast; the planter's restart recovery re-runs
	// the broadcast branch and lands back here, so the crash window
	// between the broadcast-state write and this registration
	// self-heals.
	_, err = b.cfg.AnchoringWatcher.Register(
		ctx, tapreorg.RegistrationSpec{
			Site:      MintSiteID,
			Triggers:  triggers,
			MatchData: blob,
			Payload:   blob,
			MatchKey:  matchKey,
			Threshold: b.cfg.AnchoringThreshold,
		}, nil,
	)
	if err != nil {
		return fmt.Errorf("unable to register mint anchoring: %w",
			err)
	}

	return nil
}

// waitForMintAnchoring polls the registry until the batch's anchoring
// reaches a delivered positive phase, then feeds the cultivator's
// confirmation channel with an event synthesized from the witness
// (fetching the full block for proof construction). Terminal negative
// phases surface as errors — the site's compensation has already run.
func (b *Cultivator) waitForMintAnchoring(ctx context.Context,
	genesisTxid chainhash.Hash) (*chainntnfs.TxConfirmation, error) {

	var anchoringID tapreorg.AnchoringID
	ticker := time.NewTicker(mintAnchoringPollInterval)
	defer ticker.Stop()

	for {
		if anchoringID == 0 {
			anchoring, err := b.cfg.AnchoringWatcher.LookupByMatchKey(
				ctx, MintSiteID, genesisTxid.CloneBytes(),
			)
			if err != nil {
				return nil, err
			}
			if anchoring != nil {
				anchoringID = anchoring.ID
			}
		}

		if anchoringID != 0 {
			anchoring, err := b.cfg.AnchoringWatcher.Anchoring(
				ctx, anchoringID,
			)
			if err != nil {
				return nil, err
			}

			switch anchoring.DeliveredPhase.(type) {
			case tapreorg.Witnessed, tapreorg.Buried:
				witness, err := tapreorg.WitnessContext(
					anchoring, anchoring.DeliveredPhase,
				)
				if err != nil {
					return nil, err
				}

				block, err := b.cfg.ChainBridge.GetBlock(
					ctx, witness.W.BlockHash(),
				)
				if err != nil {
					return nil, fmt.Errorf("unable to "+
						"fetch witness block: %w",
						err)
				}

				blockHash := witness.W.BlockHash()

				return &chainntnfs.TxConfirmation{
					Tx:          witness.W.Tx(),
					BlockHash:   &blockHash,
					BlockHeight: witness.W.Height(),
					TxIndex:     witness.W.TxIndex(),
					Block:       block,
				}, nil

			case tapreorg.Abandoned:
				return nil, fmt.Errorf("mint anchoring %d "+
					"abandoned: genesis inputs claimed "+
					"by a buried conflicting transaction",
					anchoringID)

			case tapreorg.Withdrawn:
				return nil, fmt.Errorf("mint anchoring %d "+
					"withdrawn", anchoringID)
			}
		}

		select {
		case <-ticker.C:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-b.Quit:
			return nil, fmt.Errorf("cultivator shutting down")
		}
	}
}

// mintAnchoringPollInterval is the cadence at which a cultivator
// reads the registry while waiting on its anchoring; minting latency
// tolerates polling comfortably.
const mintAnchoringPollInterval = 10 * time.Second
