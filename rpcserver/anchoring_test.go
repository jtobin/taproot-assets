package rpcserver

// anchoring_test.go contains unit tests for the ListAnchorings
// marshalling.

import (
	"testing"

	"github.com/lightninglabs/taproot-assets/tapdb"
	"github.com/lightninglabs/taproot-assets/tapreorg"
	"github.com/stretchr/testify/require"
)

// TestMarshalAnchoring pins the observability listing's wire shape:
// the phase fields carry the stable phase names — so any listed value
// round-trips through the request's phase filter verbatim — with the
// evidence renderings and delivery bookkeeping alongside.
func TestMarshalAnchoring(t *testing.T) {
	t.Parallel()

	summary := tapdb.AnchoringSummary{
		ID:                7,
		Site:              "minter",
		Threshold:         6,
		CreatedHeight:     812_000,
		Phase:             tapreorg.PhaseCodeBuried,
		PhaseDetail:       "buried(deadbeef@812003)",
		Delivered:         tapreorg.PhaseCodeWitnessed,
		DeliveredDetail:   "witnessed(deadbeef@812003)",
		WitnessTxid:       []byte{0xde, 0xad},
		Stuck:             true,
		DeliveryAttempts:  3,
		LastDeliveryError: "handler down",
		TerminalAt:        1_700_000_000,
		NumCandidates:     2,
	}

	anchoring := marshalAnchoring(summary)
	require.Equal(t, int64(7), anchoring.Id)
	require.Equal(t, "minter", anchoring.Site)
	require.Equal(t, "buried", anchoring.Phase)
	require.Equal(t, summary.PhaseDetail, anchoring.PhaseDetail)
	require.Equal(t, "witnessed", anchoring.DeliveredPhase)
	require.Equal(
		t, summary.DeliveredDetail, anchoring.DeliveredPhaseDetail,
	)
	require.Equal(t, summary.WitnessTxid, anchoring.WitnessTxid)
	require.True(t, anchoring.Stuck)
	require.Equal(t, uint32(3), anchoring.DeliveryAttempts)
	require.Equal(t, "handler down", anchoring.LastDeliveryError)
	require.Equal(t, int64(1_700_000_000), anchoring.TerminalAt)
	require.Equal(t, uint32(2), anchoring.NumCandidates)

	// Every phase name the response can carry resolves back
	// through the filter's parser.
	codes := []tapreorg.PhaseCode{
		tapreorg.PhaseCodeUnwitnessed, tapreorg.PhaseCodeWitnessed,
		tapreorg.PhaseCodeConflicted, tapreorg.PhaseCodeBuried,
		tapreorg.PhaseCodeAbandoned, tapreorg.PhaseCodeWithdrawn,
	}
	for _, code := range codes {
		back, err := tapreorg.PhaseCodeFromName(code.String())
		require.NoError(t, err)
		require.Equal(t, code, back)
	}
}
