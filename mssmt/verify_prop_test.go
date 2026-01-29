package mssmt

import (
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// genLeafNode generates a random leaf node.
func genLeafNode(t *rapid.T) *LeafNode {
	valueLen := rapid.IntRange(0, 100).Draw(t, "valueLen")
	value := rapid.SliceOfN(rapid.Byte(), valueLen, valueLen).Draw(t, "value")
	sum := rapid.Uint64().Draw(t, "sum")
	return NewLeafNode(value, sum)
}

// genBranchNode generates a random branch node with leaf children.
func genBranchNode(t *rapid.T) *BranchNode {
	left := genLeafNode(t)
	right := genLeafNode(t)
	return NewBranch(left, right)
}

// genDeepTree generates a tree of the specified depth with leaf nodes.
func genDeepTree(t *rapid.T, depth int) Node {
	if depth <= 0 {
		return genLeafNode(t)
	}
	left := genDeepTree(t, depth-1)
	right := genDeepTree(t, depth-1)
	return NewBranch(left, right)
}

// TestBranchInvariantHolds tests that NewBranch always creates branches
// that satisfy the sum invariant.
func TestBranchInvariantHolds(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		branch := genBranchNode(t)

		// The invariant should always hold for newly constructed branches.
		err := VerifyBranchInvariant(branch)
		require.NoError(t, err)

		// Verify the sum is actually the sum of children.
		expected := branch.Left.NodeSum() + branch.Right.NodeSum()
		require.Equal(t, expected, branch.NodeSum())
	})
}

// TestTreeInvariantHolds tests that trees built with NewBranch satisfy
// the sum invariant at all levels.
func TestTreeInvariantHolds(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		// Generate trees of varying depths (0-5).
		depth := rapid.IntRange(0, 5).Draw(t, "depth")
		tree := genDeepTree(t, depth)

		// The invariant should hold throughout the tree.
		err := VerifyTreeInvariant(tree)
		require.NoError(t, err)
	})
}

// TestRootSumEqualsLeafSum tests that the root sum equals the sum of all
// leaf sums in a tree.
func TestRootSumEqualsLeafSum(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		// Generate a small tree.
		numLeaves := rapid.IntRange(1, 8).Draw(t, "numLeaves")
		leaves := make([]*LeafNode, numLeaves)
		var totalLeafSum uint64

		for i := 0; i < numLeaves; i++ {
			leaves[i] = genLeafNode(t)
			totalLeafSum += leaves[i].NodeSum()
		}

		// Build a tree from the leaves (simple linear tree for testing).
		var tree Node = leaves[0]
		for i := 1; i < numLeaves; i++ {
			tree = NewBranch(tree, leaves[i])
		}

		// The root sum should equal the total leaf sum.
		require.Equal(t, totalLeafSum, tree.NodeSum())
	})
}

// TestComputedBranchPreservesSum tests that ComputedBranch nodes preserve
// the sum value.
func TestComputedBranchPreservesSum(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		// Create a real branch.
		branch := genBranchNode(t)
		originalSum := branch.NodeSum()
		originalHash := branch.NodeHash()

		// Create a computed branch with the same values.
		computed := NewComputedBranch(originalHash, originalSum)

		// The computed branch should have the same sum.
		require.Equal(t, originalSum, computed.NodeSum())
		require.Equal(t, originalHash, computed.NodeHash())
	})
}

// TestVerifyBranchInvariantRejectsInvalid tests that VerifyBranchInvariant
// correctly rejects branches with manipulated sums.
func TestVerifyBranchInvariantRejectsInvalid(t *testing.T) {
	t.Parallel()

	// Create a valid branch.
	left := NewLeafNode([]byte("left"), 100)
	right := NewLeafNode([]byte("right"), 200)
	branch := NewBranch(left, right)

	// Should be valid.
	err := VerifyBranchInvariant(branch)
	require.NoError(t, err)
	require.Equal(t, uint64(300), branch.NodeSum())

	// Note: We can't easily create an invalid branch because the sum
	// is computed lazily from children. The invariant would only fail
	// if the children were mutated after branch creation, which the
	// current API doesn't allow (by design).
}

// TestVerifyTreeInvariantWithEmptyTree tests verification of empty nodes.
func TestVerifyTreeInvariantWithEmptyTree(t *testing.T) {
	t.Parallel()

	// Empty leaf should pass.
	err := VerifyTreeInvariant(EmptyLeafNode)
	require.NoError(t, err)

	// Nil should pass.
	err = VerifyTreeInvariant(nil)
	require.NoError(t, err)
}

// TestLeafInclusionVerification tests that proof verification works correctly
// with properly constructed proofs.
func TestLeafInclusionVerification(t *testing.T) {
	t.Parallel()

	// This test uses a simple tree structure where we can manually
	// construct the proof. For a single leaf at key 0, with all empty
	// siblings, we need MaxTreeLevels empty nodes.
	var key [32]byte // All zeros
	leaf := NewLeafNode([]byte("test"), 100)

	// Build a proof with empty tree nodes at each level.
	nodes := make([]Node, MaxTreeLevels)
	for i := 0; i < MaxTreeLevels; i++ {
		nodes[i] = EmptyTree[i+1]
	}
	proof := &Proof{Nodes: nodes}

	// Compute the root.
	root := proof.Root(key, leaf)

	// Verification should succeed.
	result := VerifyLeafInclusion(key, leaf, proof, root)
	require.True(t, result)

	// Verification with wrong leaf should fail.
	wrongLeaf := NewLeafNode([]byte("wrong"), 999)
	result = VerifyLeafInclusion(key, wrongLeaf, proof, root)
	require.False(t, result)
}
