package mssmt

import "fmt"

// VerifyBranchInvariant checks that a branch node's sum equals the sum of its
// children's sums. This is the fundamental MS-SMT invariant that prevents
// asset inflation.
//
// Note: This function only works for branches with actual children (not
// ComputedNode or NewComputedBranch nodes which don't have children).
func VerifyBranchInvariant(b *BranchNode) error {
	if b.Left == nil || b.Right == nil {
		return fmt.Errorf("branch has nil children, cannot verify")
	}

	leftSum := b.Left.NodeSum()
	rightSum := b.Right.NodeSum()
	expected := leftSum + rightSum
	actual := b.NodeSum()

	if actual != expected {
		return fmt.Errorf("branch sum invariant violated: "+
			"left=%d + right=%d = %d, but branch has %d",
			leftSum, rightSum, expected, actual)
	}

	return nil
}

// VerifyTreeInvariant recursively verifies that all branch nodes in a tree
// satisfy the sum invariant. Returns nil if the tree is valid, or an error
// describing the first violation found.
//
// Note: This only verifies branches that have actual children. ComputedNode
// and ComputedBranch nodes (which only store hash and sum) cannot be verified
// as their children are not available.
func VerifyTreeInvariant(node Node) error {
	return verifyTreeInvariantWithDepth(node, 0)
}

func verifyTreeInvariantWithDepth(node Node, depth int) error {
	if node == nil {
		return nil
	}

	switch n := node.(type) {
	case *BranchNode:
		// Skip branches without children (computed branches).
		if n.Left == nil || n.Right == nil {
			return nil
		}

		// Verify this branch.
		if err := VerifyBranchInvariant(n); err != nil {
			return fmt.Errorf("at depth %d: %w", depth, err)
		}

		// Recursively verify children.
		if err := verifyTreeInvariantWithDepth(n.Left, depth+1); err != nil {
			return err
		}
		if err := verifyTreeInvariantWithDepth(n.Right, depth+1); err != nil {
			return err
		}

	case *CompactedLeafNode:
		// Compacted leaves represent a subtree; we can't verify the
		// internal structure without extracting it.
		return nil

	case *LeafNode:
		// Leaf nodes have no children to verify.
		return nil

	case ComputedNode:
		// Computed nodes only have hash and sum, no children.
		return nil
	}

	return nil
}

// VerifyLeafInclusion verifies that a leaf is correctly included in a tree
// by checking that the proof reconstructs the expected root.
func VerifyLeafInclusion(key [32]byte, leaf *LeafNode, proof *Proof,
	expectedRoot Node) bool {

	reconstructedRoot := proof.Root(key, leaf)
	return IsEqualNode(reconstructedRoot, expectedRoot)
}
