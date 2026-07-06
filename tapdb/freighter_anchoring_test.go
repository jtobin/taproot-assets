package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"math/rand"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

// blockContextFor synthesizes a block context (hash, header, merkle
// proof) containing the given transaction, the way the re-org
// watcher's sensing enriches witnesses.
func blockContextFor(t *testing.T, tx *wire.MsgTx,
	nonce uint32) (chainhash.Hash, wire.BlockHeader,
	proof.TxMerkleProof) {

	header := wire.BlockHeader{
		Version: 2,
		Nonce:   nonce,
	}
	merkle, err := proof.NewTxMerkleProof([]*wire.MsgTx{tx}, 0)
	require.NoError(t, err)

	return header.BlockHash(), header, *merkle
}

// TestPorterAnchoringPersistence drives a transfer through the porter
// site's persistence cycle against a real database: the phase-1
// pending write, the rebuilt-and-applied confirmation, a re-organized
// re-confirmation (convergence: no duplicated state, refreshed block
// info), the potency-tier unconfirm, and act-level abandonment with
// full compensation.
func TestPorterAnchoringPersistence(t *testing.T) {
	t.Parallel()

	db := NewTestDB(t)
	_, assetsStore := newAssetStoreFromDB(db.BaseDB)
	ctx := context.Background()

	// The registry-style executor: full query set, one transaction.
	executor := NewTransactionExecutor(
		db, func(tx *sql.Tx) *sqlc.Queries {
			return db.WithTx(tx)
		},
	)

	// One confirmed input asset.
	targetScriptKey := asset.NewScriptKeyBip86(keychain.KeyDescriptor{
		PubKey: test.RandPubKey(t),
		KeyLocator: keychain.KeyLocator{
			Family: test.RandInt[keychain.KeyFamily](),
			Index:  uint32(test.RandInt[int32]()),
		},
	})

	assetGen := newAssetGenerator(t, 1, 1)
	assetGen.genAssets(t, assetsStore, []assetDesc{{
		assetGen:    assetGen.assetGens[0],
		anchorPoint: assetGen.anchorPoints[0],
		scriptKey:   &targetScriptKey,
		amt:         16,
	}})

	allAssets, err := assetsStore.FetchAllAssets(ctx, true, false, nil)
	require.NoError(t, err)
	require.Len(t, allAssets, 1)
	inputAsset := allAssets[0]
	assetID := inputAsset.ID()

	inputAnchorPoint := wire.OutPoint{
		Hash:  assetGen.anchorTxs[0].TxHash(),
		Index: 0,
	}

	// The input's proof file, stored where the rebuild will fetch
	// it (asset_proofs, keyed by the asset row).
	inputProof := randProof(t, inputAsset.Asset)
	inputFile, err := proof.NewFile(proof.V0, *inputProof)
	require.NoError(t, err)
	var inputFileBuf bytes.Buffer
	require.NoError(t, inputFile.Encode(&inputFileBuf))

	var inputAssetDBID int64
	err = db.DB.QueryRowContext(
		ctx, "SELECT assets.asset_id FROM assets "+
			"JOIN script_keys ON assets.script_key_id = "+
			"script_keys.script_key_id "+
			"WHERE script_keys.tweaked_script_key = $1",
		inputAsset.ScriptKey.PubKey.SerializeCompressed(),
	).Scan(&inputAssetDBID)
	require.NoError(t, err)
	require.NoError(t, db.UpsertAssetProofByID(ctx, ProofUpdateByID{
		AssetID:   inputAssetDBID,
		ProofFile: inputFileBuf.Bytes(),
	}))

	// The transfer: one input, two outputs (receiver + change).
	newAnchorTx := wire.NewMsgTx(2)
	newAnchorTx.AddTxIn(&wire.TxIn{PreviousOutPoint: inputAnchorPoint})
	newAnchorTx.TxIn[0].SignatureScript = []byte{}
	newAnchorTx.AddTxOut(&wire.TxOut{
		PkScript: bytes.Repeat([]byte{0x01}, 34),
		Value:    1000,
	})
	newAnchorTx.AddTxOut(&wire.TxOut{
		PkScript: bytes.Repeat([]byte{0x02}, 34),
		Value:    1000,
	})
	anchorTxHash := newAnchorTx.TxHash()

	newScriptKey := asset.NewScriptKeyBip86(keychain.KeyDescriptor{
		PubKey: test.RandPubKey(t),
		KeyLocator: keychain.KeyLocator{
			Index:  uint32(rand.Int31()),
			Family: keychain.KeyFamily(rand.Int31()),
		},
	})
	newScriptKey2 := asset.NewScriptKeyBip86(keychain.KeyDescriptor{
		PubKey: test.RandPubKey(t),
		KeyLocator: keychain.KeyLocator{
			Index:  uint32(rand.Int31()),
			Family: keychain.KeyFamily(rand.Int31()),
		},
	})
	const newAmt = 9

	receiverAsset := inputAsset.Copy()
	receiverAsset.ScriptKey = newScriptKey
	receiverProof := randProof(t, receiverAsset)
	receiverProofBytes, err := receiverProof.Bytes()
	require.NoError(t, err)

	senderAsset := inputAsset.Copy()
	senderAsset.ScriptKey = newScriptKey2
	senderProof := randProof(t, senderAsset)
	senderProofBytes, err := senderProof.Bytes()
	require.NoError(t, err)

	newWitness := asset.Witness{
		PrevID:    &asset.PrevID{},
		TxWitness: [][]byte{{0x01}, {0x02}},
	}
	rootHash := [32]byte{0x10}
	makeAnchor := func(index uint32, script byte) tapfreighter.Anchor {
		return tapfreighter.Anchor{
			Value: 1000,
			OutPoint: wire.OutPoint{
				Hash:  anchorTxHash,
				Index: index,
			},
			InternalKey: keychain.KeyDescriptor{
				PubKey: test.RandPubKey(t),
				KeyLocator: keychain.KeyLocator{
					Family: keychain.KeyFamily(
						rand.Int31(),
					),
					Index: uint32(test.RandInt[int32]()),
				},
			},
			TaprootAssetRoot: bytes.Repeat([]byte{0x1}, 32),
			MerkleRoot:       bytes.Repeat([]byte{0x1}, 32),
			PkScript: bytes.Repeat(
				[]byte{script}, 34,
			),
		}
	}

	parcel := &tapfreighter.OutboundParcel{
		AnchorTx:           newAnchorTx,
		AnchorTxHeightHint: 1450,
		TransferTime:       time.Now(),
		ChainFees:          100,
		Inputs: []tapfreighter.TransferInput{{
			PrevID: asset.PrevID{
				OutPoint: inputAnchorPoint,
				ID:       assetID,
				ScriptKey: asset.ToSerialized(
					inputAsset.ScriptKey.PubKey,
				),
			},
			Amount: inputAsset.Amount,
		}},
		Outputs: []tapfreighter.TransferOutput{{
			Anchor:         makeAnchor(0, 0x01),
			ScriptKey:      newScriptKey,
			ScriptKeyLocal: true,
			Amount:         newAmt,
			WitnessData:    []asset.Witness{newWitness},
			SplitCommitmentRoot: mssmt.NewComputedNode(
				rootHash, 100,
			),
			ProofSuffix: receiverProofBytes,
			Position:    0,
		}, {
			Anchor:         makeAnchor(1, 0x02),
			ScriptKey:      newScriptKey2,
			ScriptKeyLocal: true,
			Amount:         inputAsset.Amount - newAmt,
			WitnessData:    []asset.Witness{newWitness},
			SplitCommitmentRoot: mssmt.NewComputedNode(
				rootHash, 100,
			),
			ProofSuffix: senderProofBytes,
			Position:    1,
		}},
	}

	leaseOwner := fn.ToArray[[32]byte](test.RandBytes(32))
	leaseExpiry := time.Now().Add(time.Hour)

	// Phase 1: the pending write, inside a caller-owned transaction
	// (as the anchoring registration runs it).
	err = executor.ExecTx(
		ctx, WriteTxOption(), func(q *sqlc.Queries) error {
			return assetsStore.ApplyPendingParcel(
				ctx, q, parcel, leaseOwner, leaseExpiry,
			)
		},
	)
	require.NoError(t, err)

	parcels, err := assetsStore.QueryParcels(ctx, nil, true)
	require.NoError(t, err)
	require.Len(t, parcels, 1)

	// Leased assets are included: the pending write leases the
	// input.
	assetCount := func() int {
		assets, err := assetsStore.FetchAllAssets(
			ctx, true, true, nil,
		)
		require.NoError(t, err)

		return len(assets)
	}
	require.Equal(t, 1, assetCount())

	// rebuildAndApply mirrors the porter site's OnWitnessed: rebuild
	// the confirmation from stored state plus a block context, then
	// apply it, in one transaction.
	rebuildAndApply := func(blockHash chainhash.Hash,
		header wire.BlockHeader, merkle proof.TxMerkleProof,
		height, txIndex uint32) error {

		return executor.ExecTx(
			ctx, WriteTxOption(), func(q *sqlc.Queries) error {
				conf, burns, err := assetsStore.
					RebuildAnchorConfirm(
						ctx, q, newAnchorTx,
						blockHash, height, txIndex,
						header, merkle, "test note",
					)
				if err != nil {
					return err
				}

				_, err = assetsStore.ApplyAnchorTxConfirm(
					ctx, q, conf, burns,
				)

				return err
			},
		)
	}

	// The anchor confirms in block A.
	blockHashA, headerA, merkleA := blockContextFor(t, newAnchorTx, 1)
	require.NoError(t, rebuildAndApply(blockHashA, headerA, merkleA, 600, 0))

	// The input is spent, two new assets materialized, and the
	// parcel is no longer pending (proof delivery flags aside).
	assets, err := assetsStore.FetchAllAssets(ctx, true, true, nil)
	require.NoError(t, err)
	require.Len(t, assets, 3)

	spentCount := 0
	for _, dbAsset := range assets {
		if dbAsset.IsSpent {
			spentCount++
		}
	}
	require.Equal(t, 1, spentCount)

	// Convergence under re-confirmation: the same transaction
	// re-confirms in block B after a re-org. No duplicate rows; the
	// chain info refreshes.
	blockHashB, headerB, merkleB := blockContextFor(t, newAnchorTx, 2)
	require.NoError(t, rebuildAndApply(blockHashB, headerB, merkleB, 601, 0))
	require.Equal(t, 3, assetCount())

	transfers, err := db.QueryAssetTransfers(ctx, sqlc.QueryAssetTransfersParams{
		AnchorTxHash: anchorTxHash[:],
	})
	require.NoError(t, err)
	require.Len(t, transfers, 1)

	chainTx, err := db.FetchChainTx(ctx, anchorTxHash[:])
	require.NoError(t, err)
	require.Equal(t, blockHashB[:], chainTx.BlockHash)

	// The potency-tier downgrade: the witness was lost, the
	// confirmation is withdrawn, nothing else moves.
	err = executor.ExecTx(
		ctx, WriteTxOption(), func(q *sqlc.Queries) error {
			return assetsStore.ApplyAnchorTxUnconfirm(
				ctx, q, anchorTxHash,
			)
		},
	)
	require.NoError(t, err)

	chainTx, err = db.FetchChainTx(ctx, anchorTxHash[:])
	require.NoError(t, err)
	require.Nil(t, chainTx.BlockHash)
	require.Equal(t, 3, assetCount())

	// It re-confirms once more (block B again).
	require.NoError(t, rebuildAndApply(blockHashB, headerB, merkleB, 601, 0))

	// Act-level loss: a conflicting transaction buried. Everything
	// staked on this transfer reverses.
	err = executor.ExecTx(
		ctx, WriteTxOption(), func(q *sqlc.Queries) error {
			return assetsStore.ApplyTransferAbandonment(
				ctx, q, anchorTxHash,
			)
		},
	)
	require.NoError(t, err)

	// The materialized outputs are gone, the input is unspent
	// again, and its lease is released (visible without leased
	// inclusion).
	assets, err = assetsStore.FetchAllAssets(ctx, true, false, nil)
	require.NoError(t, err)
	require.Len(t, assets, 1)
	require.False(t, assets[0].IsSpent)

	// The chain transaction is unconfirmed and the transfer is
	// superseded: it must not be resumed.
	chainTx, err = db.FetchChainTx(ctx, anchorTxHash[:])
	require.NoError(t, err)
	require.Nil(t, chainTx.BlockHash)

	parcels, err = assetsStore.QueryParcels(ctx, nil, true)
	require.NoError(t, err)
	require.Len(t, parcels, 0)

	var superseded bool
	err = db.DB.QueryRowContext(
		ctx, "SELECT superseded FROM asset_transfers "+
			"WHERE anchor_txn_id IN (SELECT txn_id "+
			"FROM chain_txns WHERE txid = $1)",
		anchorTxHash[:],
	).Scan(&superseded)
	require.NoError(t, err)
	require.True(t, superseded)
}
