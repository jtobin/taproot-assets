package tapcustody

import (
	"bytes"
	"context"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapreorg"
	"github.com/stretchr/testify/require"
)

// singleProofGenesisFile returns a single-proof file whose tip has no
// prior asset outpoint — the shape of a genesis-shaped receive.
func singleProofGenesisFile(t *testing.T,
	anchorTx *wire.MsgTx) *proof.File {

	t.Helper()

	scriptKey := asset.NewScriptKey(test.RandPubKey(t))
	p := proof.Proof{
		PrevOut: wire.OutPoint{}, // No prior outpoint: genesis.
		BlockHeader: wire.BlockHeader{
			Version:    1,
			MerkleRoot: chainhash.Hash{0xaa, 0xbb},
		},
		BlockHeight:   700,
		AnchorTx:      *anchorTx,
		TxMerkleProof: proof.TxMerkleProof{},
		Asset: asset.Asset{
			Version:   asset.V0,
			Amount:    1_000,
			ScriptKey: scriptKey,
			PrevWitnesses: []asset.Witness{
				{PrevID: &asset.PrevID{}},
			},
		},
		InclusionProof: proof.TaprootProof{
			InternalKey: test.RandPubKey(t),
			OutputIndex: 0,
		},
	}
	file, err := proof.NewFile(proof.V0, p)
	require.NoError(t, err)

	return file
}

// TestRegisterReceiveAnchoringGenesisShape asserts that a single-proof
// genesis file — no derivable asset-bearing trigger — takes the seed
// path: the anchor tx is recorded as the anchoring's candidate spend
// directly, without a trigger set to watch.
func TestRegisterReceiveAnchoringGenesisShape(t *testing.T) {
	t.Parallel()

	registrar := tapreorg.NewMockRegistrar()
	c := &Custodian{
		cfg: &Config{
			AnchoringWatcher:   registrar,
			AnchoringThreshold: 6,
		},
	}

	fundingOp := wire.OutPoint{Hash: chainhash.Hash{0x11}, Index: 0}
	anchorTx := wire.NewMsgTx(2)
	anchorTx.AddTxIn(wire.NewTxIn(&fundingOp, nil, nil))
	anchorTx.AddTxOut(wire.NewTxOut(1_000, []byte{0x51, 0xaa}))

	file := singleProofGenesisFile(t, anchorTx)
	require.NoError(t, c.RegisterReceiveAnchoring(
		context.Background(), file,
	))

	anchorings, err := registrar.AllAnchorings(
		context.Background(), ReceiveSiteID,
	)
	require.NoError(t, err)
	require.Len(t, anchorings, 1)

	a := anchorings[0]

	// A genesis-shape registration passes an empty trigger set —
	// the seed candidate is what's watched.
	require.Zero(t, a.Triggers.Len())

	// The seed is durably recorded and the mock's phase reflects
	// the immediate Witnessed state (production's watcher would
	// reach the same phase through the conf subscription on the
	// candidate).
	require.Len(t, a.Spends, 1)
	require.Equal(t, anchorTx.TxHash(), a.Spends[0].W.TxHash())
	require.True(t, a.Spends[0].OnChain)
	require.NotNil(t, a.Spends[0].BlockHeader)
	require.NotNil(t, a.Spends[0].MerkleProof)
	require.IsType(t, tapreorg.Witnessed{}, a.Phase)
}

// TestRegisterReceiveAnchoringGenesisShapeIdempotent asserts the
// genesis-shape path is idempotent per anchor transaction: a
// second registration for the same file does not create a duplicate
// anchoring, matching the multi-proof path's contract.
func TestRegisterReceiveAnchoringGenesisShapeIdempotent(t *testing.T) {
	t.Parallel()

	registrar := tapreorg.NewMockRegistrar()
	c := &Custodian{
		cfg: &Config{
			AnchoringWatcher:   registrar,
			AnchoringThreshold: 6,
		},
	}

	fundingOp := wire.OutPoint{Hash: chainhash.Hash{0x22}, Index: 0}
	anchorTx := wire.NewMsgTx(2)
	anchorTx.AddTxIn(wire.NewTxIn(&fundingOp, nil, nil))
	anchorTx.AddTxOut(wire.NewTxOut(1_000, []byte{0x51, 0xbb}))

	file := singleProofGenesisFile(t, anchorTx)
	ctx := context.Background()
	require.NoError(t, c.RegisterReceiveAnchoring(ctx, file))
	require.NoError(t, c.RegisterReceiveAnchoring(ctx, file))

	anchorings, err := registrar.AllAnchorings(ctx, ReceiveSiteID)
	require.NoError(t, err)
	require.Len(t, anchorings, 1)
}

// TestReceiveTriggerPointsGenesisShape pins the current signal from
// receiveTriggerPoints for genesis-shaped files: it returns
// ErrNoTriggers, which RegisterReceiveAnchoring routes onto the seed
// path.
func TestReceiveTriggerPointsGenesisShape(t *testing.T) {
	t.Parallel()

	anchorTx := wire.NewMsgTx(2)
	anchorTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))
	anchorTx.AddTxOut(wire.NewTxOut(1_000, []byte{0x51, 0xcc}))

	file := singleProofGenesisFile(t, anchorTx)
	tip, err := file.ProofAt(0)
	require.NoError(t, err)

	_, err = receiveTriggerPoints(file, tip)
	require.ErrorIs(t, err, ErrNoTriggers)
}

// TestGenesisSeedCandidateFromFile asserts the seed candidate built
// from a genesis-shaped file's tip is fully enriched: witness located,
// block header and merkle proof carried, satisfying verdict.
func TestGenesisSeedCandidateFromFile(t *testing.T) {
	t.Parallel()

	anchorTx := wire.NewMsgTx(2)
	anchorTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))
	anchorTx.AddTxOut(wire.NewTxOut(1_000, []byte{0x51, 0xdd}))

	file := singleProofGenesisFile(t, anchorTx)
	tip, err := file.ProofAt(0)
	require.NoError(t, err)

	seed, err := genesisSeedCandidate(tip)
	require.NoError(t, err)

	require.Equal(t, anchorTx.TxHash(), seed.W.TxHash())
	require.Equal(t, tip.BlockHeight, seed.W.Height())
	require.True(t, seed.OnChain)
	require.Equal(t, tapreorg.VerdictSatisfies, seed.Verdict)
	require.False(t, seed.ActCertified)
	require.NotNil(t, seed.BlockHeader)
	require.NotNil(t, seed.MerkleProof)

	// The tip's own tx round-trips through the witness.
	var recovered bytes.Buffer
	require.NoError(t, seed.W.Tx().Serialize(&recovered))
	var original bytes.Buffer
	require.NoError(t, anchorTx.Serialize(&original))
	require.Equal(t, original.Bytes(), recovered.Bytes())
}

// TestRegisterReceiveAnchoringUnwatchable asserts that a genesis-shape
// file with no block context returns ErrUnwatchable: callers see the
// outcome legibly rather than mistaking a warning-log-and-nil for
// successful registration.
func TestRegisterReceiveAnchoringUnwatchable(t *testing.T) {
	t.Parallel()

	registrar := tapreorg.NewMockRegistrar()
	c := &Custodian{
		cfg: &Config{
			AnchoringWatcher:   registrar,
			AnchoringThreshold: 6,
		},
	}

	fundingOp := wire.OutPoint{Hash: chainhash.Hash{0x33}, Index: 0}
	anchorTx := wire.NewMsgTx(2)
	anchorTx.AddTxIn(wire.NewTxIn(&fundingOp, nil, nil))
	anchorTx.AddTxOut(wire.NewTxOut(1_000, []byte{0x51, 0xee}))

	// singleProofGenesisFile sets BlockHeight to 700; force the stub
	// case by rebuilding a proof file with height 0.
	scriptKey := asset.NewScriptKey(test.RandPubKey(t))
	p := proof.Proof{
		PrevOut:       wire.OutPoint{},
		BlockHeader:   wire.BlockHeader{Version: 1},
		BlockHeight:   0,
		AnchorTx:      *anchorTx,
		TxMerkleProof: proof.TxMerkleProof{},
		Asset: asset.Asset{
			Version:   asset.V0,
			Amount:    1_000,
			ScriptKey: scriptKey,
			PrevWitnesses: []asset.Witness{
				{PrevID: &asset.PrevID{}},
			},
		},
		InclusionProof: proof.TaprootProof{
			InternalKey: test.RandPubKey(t),
			OutputIndex: 0,
		},
	}
	file, err := proof.NewFile(proof.V0, p)
	require.NoError(t, err)

	err = c.RegisterReceiveAnchoring(context.Background(), file)
	require.ErrorIs(t, err, ErrUnwatchable)

	// Nothing was registered.
	anchorings, err := registrar.AllAnchorings(
		context.Background(), ReceiveSiteID,
	)
	require.NoError(t, err)
	require.Empty(t, anchorings)
}
