package tapreorg

import (
	"context"
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/proof"
)

// Registrar is the watcher surface a subsystem uses to stake local
// state on chain outcomes and to observe the phases the watcher has
// delivered: registration, identity lookup across every phase, and
// per-anchoring reads. Implemented by *Watcher; subsystem tests use
// MockRegistrar.
type Registrar interface {
	// Register stakes a new anchoring, running the optional phase-1
	// write in the registration transaction.
	Register(ctx context.Context, spec RegistrationSpec,
		phase1 func(context.Context, RegistryTx,
			AnchoringID) error) (AnchoringID, error)

	// AllAnchorings reads one site's anchorings across every phase,
	// settled ones included.
	AllAnchorings(ctx context.Context,
		site SiteID) ([]*Anchoring, error)

	// Anchoring reads a single anchoring by identifier.
	Anchoring(ctx context.Context, id AnchoringID) (*Anchoring, error)
}

// A compile-time assertion that the watcher provides the registrar
// surface.
var _ Registrar = (*Watcher)(nil)

// MockRegistrar is an in-memory Registrar for subsystem unit tests: it
// records registrations and lets a test flip an anchoring's delivered
// phase — with a properly located, block-enriched witness — the way
// the real watcher would after sensing and delivery. Phase-1 writes
// are not run: they are transaction-scoped database work that unit
// tests exercise separately.
type MockRegistrar struct {
	mu         sync.Mutex
	nextID     AnchoringID
	failNext   error
	anchorings map[AnchoringID]*Anchoring
}

// NewMockRegistrar returns an empty mock registrar.
func NewMockRegistrar() *MockRegistrar {
	return &MockRegistrar{
		anchorings: make(map[AnchoringID]*Anchoring),
	}
}

// Register records the registration and returns a fresh identifier.
func (m *MockRegistrar) Register(_ context.Context, spec RegistrationSpec,
	_ func(context.Context, RegistryTx, AnchoringID) error) (AnchoringID,
	error) {

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.failNext != nil {
		err := m.failNext
		m.failNext = nil

		return 0, err
	}

	m.nextID++
	id := m.nextID
	anchoring := &Anchoring{
		ID:             id,
		Site:           spec.Site,
		Triggers:       spec.Triggers,
		MatchData:      spec.MatchData,
		Payload:        spec.Payload,
		Threshold:      spec.Threshold,
		Phase:          Unwitnessed{},
		DeliveredPhase: Unwitnessed{},
	}
	if spec.SeedCandidate != nil {
		anchoring.Spends = []CandidateSpend{*spec.SeedCandidate}
		anchoring.Phase = Witnessed{W: spec.SeedCandidate.W}
		anchoring.DeliveredPhase = Witnessed{W: spec.SeedCandidate.W}
	}
	m.anchorings[id] = anchoring

	return id, nil
}

// FailNextRegister makes the next Register call fail with the given
// error, the way a registration transaction can fail in production.
func (m *MockRegistrar) FailNextRegister(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.failNext = err
}

// AllAnchorings lists the site's recorded anchorings.
func (m *MockRegistrar) AllAnchorings(_ context.Context,
	site SiteID) ([]*Anchoring, error) {

	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]*Anchoring, 0, len(m.anchorings))
	for _, anchoring := range m.anchorings {
		if anchoring.Site == site {
			out = append(out, anchoring)
		}
	}

	return out, nil
}

// Anchoring reads a recorded anchoring.
func (m *MockRegistrar) Anchoring(_ context.Context,
	id AnchoringID) (*Anchoring, error) {

	m.mu.Lock()
	defer m.mu.Unlock()

	anchoring, ok := m.anchorings[id]
	if !ok {
		return nil, fmt.Errorf("no anchoring with id %d", id)
	}

	return anchoring, nil
}

// ConfirmSpend marks every anchoring whose trigger set is spent by the
// given transaction as witnessed-and-delivered at the given location,
// recording a block-enriched candidate the way sensing would. It
// returns the number of anchorings confirmed.
func (m *MockRegistrar) ConfirmSpend(tx *wire.MsgTx,
	blockHash chainhash.Hash, height, txIndex uint32,
	header wire.BlockHeader, merkleProof proof.TxMerkleProof) (int,
	error) {

	witness, err := NewWitness(tx, blockHash, height, txIndex)
	if err != nil {
		return 0, err
	}

	spent := make(map[wire.OutPoint]struct{}, len(tx.TxIn))
	for _, txIn := range tx.TxIn {
		spent[txIn.PreviousOutPoint] = struct{}{}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	confirmed := 0
	for _, anchoring := range m.anchorings {
		hit := false
		for _, trigger := range anchoring.Triggers.OutPoints() {
			if _, ok := spent[trigger.OutPoint]; ok {
				hit = true
				break
			}
		}
		if !hit {
			continue
		}

		headerCopy := header
		merkleCopy := merkleProof
		anchoring.Spends = []CandidateSpend{{
			W:           witness,
			BlockHeader: &headerCopy,
			MerkleProof: &merkleCopy,
		}}
		anchoring.Phase = Witnessed{W: witness}
		anchoring.DeliveredPhase = Witnessed{W: witness}
		confirmed++
	}

	return confirmed, nil
}
