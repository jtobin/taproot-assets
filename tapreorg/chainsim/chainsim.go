// Package chainsim provides an in-memory chain implementing
// tapreorg.ChainNotifier, for property tests that drive the watcher
// through mining, re-orgs and restarts without a chain backend.
//
// Subscriptions behave like lnd's: they dispatch historically on
// registration, re-notify after re-orgs, and deliver only confirmed
// evidence. Per-subscription delivery is ordered and asynchronous, so
// chain mutations never block on consumers.
package chainsim

import (
	"context"
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/tapreorg"
	"github.com/lightningnetwork/lnd/chainntnfs"
)

// baseHeight is the height of the simulated chain's genesis tip:
// block i of the chain sits at baseHeight+i+1.
const baseHeight = 100

// queueDepth bounds per-subscription event queues; a full queue
// panics, which in a test harness indicates a runaway scenario.
const queueDepth = 1024

// simBlock is one simulated block.
type simBlock struct {
	header wire.BlockHeader
	hash   chainhash.Hash
	height uint32
	txs    []*wire.MsgTx
}

// txLocation locates a transaction in the current chain.
type txLocation struct {
	blockHash chainhash.Hash
	height    uint32
	txIndex   uint32
	tx        *wire.MsgTx
	block     *wire.MsgBlock
}

// spender describes the current confirmed spender of an outpoint.
type spender struct {
	tx         *wire.MsgTx
	txid       chainhash.Hash
	height     uint32
	inputIndex uint32
}

// eventQueue delivers one subscription's events in order without
// holding the chain lock.
type eventQueue struct {
	events chan func()
}

func newEventQueue(ctx context.Context) *eventQueue {
	q := &eventQueue{events: make(chan func(), queueDepth)}

	go func() {
		for {
			select {
			case deliver := <-q.events:
				deliver()

			case <-ctx.Done():
				return
			}
		}
	}()

	return q
}

func (q *eventQueue) push(deliver func()) {
	select {
	case q.events <- deliver:
	default:
		panic("chainsim: event queue overflow")
	}
}

// confSub is a confirmation subscription.
type confSub struct {
	ctx       context.Context
	txid      chainhash.Hash
	numConfs  uint32
	reorgChan chan struct{}
	confChan  chan *chainntnfs.TxConfirmation
	queue     *eventQueue

	// lastBlock is the block hash last reported for the tx, nil if
	// the sub last reported (or started) unconfirmed (or below its
	// depth requirement).
	lastBlock *chainhash.Hash
}

// spendSub is a spend subscription.
type spendSub struct {
	ctx       context.Context
	op        wire.OutPoint
	reorgChan chan struct{}
	spendChan chan *chainntnfs.SpendDetail
	queue     *eventQueue

	// last identifies the (txid, height) last reported as the
	// spender, nil if none.
	lastTxid   *chainhash.Hash
	lastHeight uint32
}

// epochSub is a block epoch subscription.
type epochSub struct {
	ctx       context.Context
	epochChan chan int32
	queue     *eventQueue
}

// Chain is the simulated chain.
type Chain struct {
	mu sync.Mutex

	blocks    []*simBlock
	allBlocks map[chainhash.Hash]*simBlock
	blockSeq  uint32

	confSubs  map[int]*confSub
	spendSubs map[int]*spendSub
	epochSubs map[int]*epochSub
	nextSubID int
}

// New creates an empty simulated chain at baseHeight.
func New() *Chain {
	return &Chain{
		allBlocks: make(map[chainhash.Hash]*simBlock),
		confSubs:  make(map[int]*confSub),
		spendSubs: make(map[int]*spendSub),
		epochSubs: make(map[int]*epochSub),
	}
}

// BestHeight returns the current tip height.
func (c *Chain) BestHeight() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.bestHeight()
}

func (c *Chain) bestHeight() uint32 {
	return baseHeight + uint32(len(c.blocks))
}

// MineBlock appends one block containing the given transactions and
// dispatches subscription events. It returns the new height.
func (c *Chain) MineBlock(txs ...*wire.MsgTx) uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.appendBlock(txs)
	c.dispatch()

	return c.bestHeight()
}

// MineBlocks appends n empty blocks.
func (c *Chain) MineBlocks(n int) uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i := 0; i < n; i++ {
		c.appendBlock(nil)
	}
	c.dispatch()

	return c.bestHeight()
}

// Reorg disconnects depth blocks from the tip and connects the given
// replacement blocks (outermost first). The replacement must be at
// least as long as the disconnected range, so height never decreases.
func (c *Chain) Reorg(depth int, replacement ...[]*wire.MsgTx) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if depth > len(c.blocks) {
		panic(fmt.Sprintf("chainsim: reorg depth %d exceeds chain "+
			"length %d", depth, len(c.blocks)))
	}
	if len(replacement) < depth {
		panic(fmt.Sprintf("chainsim: reorg would shrink the chain "+
			"(depth %d, %d replacement blocks)", depth,
			len(replacement)))
	}

	c.blocks = c.blocks[:len(c.blocks)-depth]
	for _, txs := range replacement {
		c.appendBlock(txs)
	}
	c.dispatch()
}

// appendBlock builds and connects one block. The caller holds the
// lock.
func (c *Chain) appendBlock(txs []*wire.MsgTx) {
	c.blockSeq++

	var prev chainhash.Hash
	if len(c.blocks) > 0 {
		prev = c.blocks[len(c.blocks)-1].hash
	}

	// The nonce makes replacement blocks distinct from what they
	// replace; the header hash is the block hash, so GetBlock and
	// conf events stay self-consistent.
	header := wire.BlockHeader{
		Version:   2,
		PrevBlock: prev,
		Nonce:     c.blockSeq,
	}
	for _, tx := range txs {
		hash := tx.TxHash()
		for i, b := range hash {
			header.MerkleRoot[i] ^= b
		}
	}

	block := &simBlock{
		header: header,
		hash:   header.BlockHash(),
		height: c.bestHeight() + 1,
		txs:    txs,
	}
	c.blocks = append(c.blocks, block)
	c.allBlocks[block.hash] = block
}

// findTx locates a transaction in the current chain. The caller holds
// the lock.
func (c *Chain) findTx(txid chainhash.Hash) *txLocation {
	for _, block := range c.blocks {
		for i, tx := range block.txs {
			if tx.TxHash() != txid {
				continue
			}

			return &txLocation{
				blockHash: block.hash,
				height:    block.height,
				txIndex:   uint32(i),
				tx:        tx,
				block:     block.msgBlock(),
			}
		}
	}

	return nil
}

// findSpender locates the confirmed spender of an outpoint in the
// current chain. The caller holds the lock.
func (c *Chain) findSpender(op wire.OutPoint) *spender {
	for _, block := range c.blocks {
		for _, tx := range block.txs {
			for i, txIn := range tx.TxIn {
				if txIn.PreviousOutPoint != op {
					continue
				}

				return &spender{
					tx:         tx,
					txid:       tx.TxHash(),
					height:     block.height,
					inputIndex: uint32(i),
				}
			}
		}
	}

	return nil
}

// msgBlock renders the simulated block as a wire block.
func (b *simBlock) msgBlock() *wire.MsgBlock {
	block := &wire.MsgBlock{Header: b.header}
	block.Transactions = append(block.Transactions, b.txs...)

	return block
}

// dispatch reconciles every subscription against the current chain.
// The caller holds the lock.
func (c *Chain) dispatch() {
	for id, sub := range c.confSubs {
		if sub.ctx.Err() != nil {
			delete(c.confSubs, id)
			continue
		}
		c.dispatchConf(sub)
	}

	for id, sub := range c.spendSubs {
		if sub.ctx.Err() != nil {
			delete(c.spendSubs, id)
			continue
		}
		c.dispatchSpend(sub)
	}

	height := int32(c.bestHeight())
	for id, sub := range c.epochSubs {
		if sub.ctx.Err() != nil {
			delete(c.epochSubs, id)
			continue
		}

		s := sub
		s.queue.push(func() {
			select {
			case s.epochChan <- height:
			case <-s.ctx.Done():
			}
		})
	}
}

// dispatchConf reconciles one confirmation subscription. The caller
// holds the lock. A subscription at numConfs fires only once the
// transaction genuinely holds that depth on the current chain, as
// lnd's notifier does.
func (c *Chain) dispatchConf(sub *confSub) {
	loc := c.findTx(sub.txid)
	if loc != nil {
		depth := c.bestHeight() - loc.height + 1
		if depth < sub.numConfs {
			loc = nil
		}
	}

	switch {
	// Newly (or differently) confirmed at depth: deliver the
	// location.
	case loc != nil && (sub.lastBlock == nil ||
		*sub.lastBlock != loc.blockHash):

		conf := &chainntnfs.TxConfirmation{
			Tx:          loc.tx,
			BlockHash:   &loc.blockHash,
			BlockHeight: loc.height,
			TxIndex:     loc.txIndex,
			Block:       loc.block,
		}
		blockHash := loc.blockHash
		sub.lastBlock = &blockHash

		s := sub
		s.queue.push(func() {
			select {
			case s.confChan <- conf:
			case <-s.ctx.Done():
			}
		})

	// Fell out of the chain (or below depth): signal the re-org.
	case loc == nil && sub.lastBlock != nil:
		sub.lastBlock = nil

		s := sub
		s.queue.push(func() {
			select {
			case s.reorgChan <- struct{}{}:
			case <-s.ctx.Done():
			}
		})
	}
}

// dispatchSpend reconciles one spend subscription. The caller holds
// the lock.
func (c *Chain) dispatchSpend(sub *spendSub) {
	sp := c.findSpender(sub.op)

	// Unchanged?
	if sp == nil && sub.lastTxid == nil {
		return
	}
	if sp != nil && sub.lastTxid != nil && sp.txid == *sub.lastTxid &&
		sp.height == sub.lastHeight {

		return
	}

	// Anything previously reported has been displaced.
	if sub.lastTxid != nil {
		s := sub
		s.queue.push(func() {
			select {
			case s.reorgChan <- struct{}{}:
			case <-s.ctx.Done():
			}
		})
		sub.lastTxid = nil
	}

	if sp == nil {
		return
	}

	op := sub.op
	detail := &chainntnfs.SpendDetail{
		SpentOutPoint:     &op,
		SpenderTxHash:     &sp.txid,
		SpendingTx:        sp.tx,
		SpenderInputIndex: sp.inputIndex,
		SpendingHeight:    int32(sp.height),
	}
	txid := sp.txid
	sub.lastTxid = &txid
	sub.lastHeight = sp.height

	s := sub
	s.queue.push(func() {
		select {
		case s.spendChan <- detail:
		case <-s.ctx.Done():
		}
	})
}

// Length returns the number of blocks on the current chain (the
// maximum re-org depth).
func (c *Chain) Length() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.blocks)
}

// TxHeight returns the height at which the given transaction sits in
// the current chain, if it does.
func (c *Chain) TxHeight(txid chainhash.Hash) (uint32, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	loc := c.findTx(txid)
	if loc == nil {
		return 0, false
	}

	return loc.height, true
}

// RegisterConfirmationsNtfn implements tapreorg.ChainNotifier.
func (c *Chain) RegisterConfirmationsNtfn(ctx context.Context,
	txid *chainhash.Hash, pkScript []byte, numConfs, heightHint uint32,
	includeBlock bool,
	reOrgChan chan struct{}) (*chainntnfs.ConfirmationEvent, chan error,
	error) {

	c.mu.Lock()
	defer c.mu.Unlock()

	subCtx, cancel := context.WithCancel(ctx)
	if numConfs == 0 {
		numConfs = 1
	}
	sub := &confSub{
		ctx:       subCtx,
		txid:      *txid,
		numConfs:  numConfs,
		reorgChan: reOrgChan,
		confChan:  make(chan *chainntnfs.TxConfirmation, 1),
		queue:     newEventQueue(subCtx),
	}

	id := c.nextSubID
	c.nextSubID++
	c.confSubs[id] = sub

	// Historical dispatch.
	c.dispatchConf(sub)

	event := &chainntnfs.ConfirmationEvent{
		Confirmed: sub.confChan,
		Cancel:    cancel,
	}

	return event, make(chan error, 1), nil
}

// RegisterSpendNtfn implements tapreorg.ChainNotifier.
func (c *Chain) RegisterSpendNtfn(ctx context.Context,
	outpoint *wire.OutPoint, pkScript []byte, heightHint uint32,
	reOrgChan chan struct{}) (chan *chainntnfs.SpendDetail, chan error,
	error) {

	c.mu.Lock()
	defer c.mu.Unlock()

	sub := &spendSub{
		ctx:       ctx,
		op:        *outpoint,
		reorgChan: reOrgChan,
		spendChan: make(chan *chainntnfs.SpendDetail, 1),
		queue:     newEventQueue(ctx),
	}

	id := c.nextSubID
	c.nextSubID++
	c.spendSubs[id] = sub

	// Historical dispatch.
	c.dispatchSpend(sub)

	return sub.spendChan, make(chan error, 1), nil
}

// RegisterBlockEpochNtfn implements tapreorg.ChainNotifier.
func (c *Chain) RegisterBlockEpochNtfn(
	ctx context.Context) (chan int32, chan error, error) {

	c.mu.Lock()
	defer c.mu.Unlock()

	sub := &epochSub{
		ctx:       ctx,
		epochChan: make(chan int32, 1),
		queue:     newEventQueue(ctx),
	}

	id := c.nextSubID
	c.nextSubID++
	c.epochSubs[id] = sub

	// Current epoch on registration, as lnd does.
	height := int32(c.bestHeight())
	sub.queue.push(func() {
		select {
		case sub.epochChan <- height:
		case <-sub.ctx.Done():
		}
	})

	return sub.epochChan, make(chan error, 1), nil
}

// CurrentHeight implements tapreorg.ChainNotifier.
func (c *Chain) CurrentHeight(ctx context.Context) (uint32, error) {
	return c.BestHeight(), nil
}

// GetBlockHash implements tapreorg.ChainNotifier.
func (c *Chain) GetBlockHash(ctx context.Context,
	blockHeight int64) (chainhash.Hash, error) {

	c.mu.Lock()
	defer c.mu.Unlock()

	idx := blockHeight - baseHeight - 1
	if idx < 0 || idx >= int64(len(c.blocks)) {
		return chainhash.Hash{}, fmt.Errorf("no block at height %d",
			blockHeight)
	}

	return c.blocks[idx].hash, nil
}

// GetBlock implements tapreorg.ChainNotifier. Orphaned blocks remain
// fetchable, as on a real node that retains them.
func (c *Chain) GetBlock(ctx context.Context,
	hash chainhash.Hash) (*wire.MsgBlock, error) {

	c.mu.Lock()
	defer c.mu.Unlock()

	block, ok := c.allBlocks[hash]
	if !ok {
		return nil, fmt.Errorf("block %v not found", hash)
	}

	return block.msgBlock(), nil
}

// A compile-time assertion that the simulator satisfies the notifier
// contract.
var _ tapreorg.ChainNotifier = (*Chain)(nil)
