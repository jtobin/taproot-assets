package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"testing"

	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/stretchr/testify/require"
)

// TestReceiveAnchoringPersistence drives received state through the
// receive site's persistence cycle: reconfirmation with refreshed
// block context (chain row and stored proof tip both updated), the
// potency-tier unconfirm, and act-level abandonment deleting the
// materialized asset.
func TestReceiveAnchoringPersistence(t *testing.T) {
	t.Parallel()

	db := NewTestDB(t)
	_, assetsStore := newAssetStoreFromDB(db.BaseDB)
	ctx := context.Background()

	executor := NewTransactionExecutor(
		db, func(tx *sql.Tx) *sqlc.Queries {
			return db.WithTx(tx)
		},
	)

	// One received asset, anchored by the generator's anchor tx.
	assetGen := newAssetGenerator(t, 1, 1)
	assetGen.genAssets(t, assetsStore, []assetDesc{{
		assetGen:    assetGen.assetGens[0],
		anchorPoint: assetGen.anchorPoints[0],
		amt:         10,
	}})

	anchorTx := assetGen.anchorTxs[0]
	anchorTxid := anchorTx.TxHash()

	assets, err := assetsStore.FetchAllAssets(ctx, true, true, nil)
	require.NoError(t, err)
	require.Len(t, assets, 1)

	// The received proof file: its tip attests the anchor tx.
	tipProof := randProof(t, assets[0].Asset)
	tipProof.AnchorTx = *anchorTx
	file, err := proof.NewFile(proof.V0, *tipProof)
	require.NoError(t, err)
	var fileBuf bytes.Buffer
	require.NoError(t, file.Encode(&fileBuf))

	var assetDBID int64
	err = db.DB.QueryRowContext(
		ctx, "SELECT assets.asset_id FROM assets "+
			"JOIN script_keys ON assets.script_key_id = "+
			"script_keys.script_key_id "+
			"WHERE script_keys.tweaked_script_key = $1",
		assets[0].ScriptKey.PubKey.SerializeCompressed(),
	).Scan(&assetDBID)
	require.NoError(t, err)
	require.NoError(t, db.UpsertAssetProofByID(ctx, ProofUpdateByID{
		AssetID:   assetDBID,
		ProofFile: fileBuf.Bytes(),
	}))

	// Reconfirmation in block A: chain row and proof tip both carry
	// the new context.
	blockHashA, headerA, merkleA := blockContextFor(t, anchorTx, 10)
	err = executor.ExecTx(
		ctx, WriteTxOption(), func(q *sqlc.Queries) error {
			return assetsStore.ApplyReceiveReconfirm(
				ctx, q, anchorTxid, blockHashA, 700, 0,
				headerA, merkleA,
			)
		},
	)
	require.NoError(t, err)

	chainTx, err := db.FetchChainTx(ctx, anchorTxid[:])
	require.NoError(t, err)
	require.Equal(t, blockHashA[:], chainTx.BlockHash)

	blob, err := db.AssetProofBlobByAssetID(ctx, assetDBID)
	require.NoError(t, err)
	patched := &proof.File{}
	require.NoError(t, patched.Decode(bytes.NewReader(blob)))
	tip, err := patched.ProofAt(uint32(patched.NumProofs() - 1))
	require.NoError(t, err)
	require.Equal(t, blockHashA, tip.BlockHeader.BlockHash())
	require.EqualValues(t, 700, tip.BlockHeight)

	// Reconfirmation in block B (the re-org case) refreshes both
	// again — convergently.
	blockHashB, headerB, merkleB := blockContextFor(t, anchorTx, 11)
	err = executor.ExecTx(
		ctx, WriteTxOption(), func(q *sqlc.Queries) error {
			return assetsStore.ApplyReceiveReconfirm(
				ctx, q, anchorTxid, blockHashB, 701, 0,
				headerB, merkleB,
			)
		},
	)
	require.NoError(t, err)

	blob, err = db.AssetProofBlobByAssetID(ctx, assetDBID)
	require.NoError(t, err)
	patched = &proof.File{}
	require.NoError(t, patched.Decode(bytes.NewReader(blob)))
	tip, err = patched.ProofAt(uint32(patched.NumProofs() - 1))
	require.NoError(t, err)
	require.Equal(t, blockHashB, tip.BlockHeader.BlockHash())

	// The potency-tier downgrade.
	err = executor.ExecTx(
		ctx, WriteTxOption(), func(q *sqlc.Queries) error {
			return assetsStore.ApplyReceiveUnconfirm(
				ctx, q, anchorTxid,
			)
		},
	)
	require.NoError(t, err)

	chainTx, err = db.FetchChainTx(ctx, anchorTxid[:])
	require.NoError(t, err)
	require.Nil(t, chainTx.BlockHash)

	// Act-level abandonment: the received asset never materialized
	// on the surviving chain.
	err = executor.ExecTx(
		ctx, WriteTxOption(), func(q *sqlc.Queries) error {
			return assetsStore.ApplyReceiveAbandonment(
				ctx, q, anchorTxid, 0,
			)
		},
	)
	require.NoError(t, err)

	assets, err = assetsStore.FetchAllAssets(ctx, true, true, nil)
	require.NoError(t, err)
	require.Len(t, assets, 0)
}

// TestReceiveAnchoringReconfirmBeforeProofs asserts that reconfirmation
// converges what exists and skips what doesn't: an anchored asset whose
// proof file is not yet materialized (the minting path's first witness
// delivery precedes the cultivator's proof writes, which that delivery
// itself unblocks) must not fail the delivery transaction.
func TestReceiveAnchoringReconfirmBeforeProofs(t *testing.T) {
	t.Parallel()

	db := NewTestDB(t)
	_, assetsStore := newAssetStoreFromDB(db.BaseDB)
	ctx := context.Background()

	executor := NewTransactionExecutor(
		db, func(tx *sql.Tx) *sqlc.Queries {
			return db.WithTx(tx)
		},
	)

	// One anchored asset with no stored proof file.
	assetGen := newAssetGenerator(t, 1, 1)
	assetGen.genAssets(t, assetsStore, []assetDesc{{
		assetGen:    assetGen.assetGens[0],
		anchorPoint: assetGen.anchorPoints[0],
		amt:         10,
	}})

	anchorTx := assetGen.anchorTxs[0]
	anchorTxid := anchorTx.TxHash()

	blockHash, header, merkle := blockContextFor(t, anchorTx, 10)
	err := executor.ExecTx(
		ctx, WriteTxOption(), func(q *sqlc.Queries) error {
			return assetsStore.ApplyReceiveReconfirm(
				ctx, q, anchorTxid, blockHash, 700, 0,
				header, merkle,
			)
		},
	)
	require.NoError(t, err)

	// The chain transaction's confirmation converged even though no
	// proof could be patched.
	chainTx, err := db.FetchChainTx(ctx, anchorTxid[:])
	require.NoError(t, err)
	require.Equal(t, blockHash[:], chainTx.BlockHash)
}
