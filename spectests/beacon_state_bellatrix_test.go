package spectests

import (
	"encoding/hex"
	"os"
	"testing"

	ssz "github.com/NilFoundation/fastssz"
	"github.com/stretchr/testify/require"
)

const TestFileName = "fixtures/beacon_state_bellatrix.ssz" // https://goerli.beaconcha.in/slot/4744352

func TestBeaconHeader_SingleProof(t *testing.T) {
	data, err := os.ReadFile(TestFileName)
	require.NoError(t, err)

	sszState := BeaconStateBellatrix{}
	err = sszState.UnmarshalSSZ(data)
	require.NoError(t, err)

	object := sszState.LatestBlockHeader

	objectTree, err := object.GetTree()
	require.NoError(t, err)

	proofAtIndex := 8

	proof, err := objectTree.Prove(proofAtIndex)
	require.NoError(t, err)

	require.Equal(t, "a064480000000000000000000000000000000000000000000000000000000000", hex.EncodeToString(proof.Leaf))
	require.Equal(t, proofAtIndex, proof.Index)
	require.Len(t, proof.Hashes, 3, "proof hashes length incorrect")
	require.Equal(t, "7859010000000000000000000000000000000000000000000000000000000000", hex.EncodeToString(proof.Hashes[0]))
	require.Equal(t, "007c0d1e0260fb9a6fa86a39569aaebc9a95aaab0180f2865da2fc25180e2242", hex.EncodeToString(proof.Hashes[1]))
	require.Equal(t, "98a517b0aa099cdfd06cdcfe71869417a00f168e8bec03ee3fa2135af2396bb6", hex.EncodeToString(proof.Hashes[2]))
}

func TestBeaconHeader_MultiProof(t *testing.T) {
	data, err := os.ReadFile(TestFileName)
	require.NoError(t, err)

	sszState := BeaconStateBellatrix{}
	err = sszState.UnmarshalSSZ(data)
	require.NoError(t, err)

	object := sszState.LatestBlockHeader

	objectTree, err := object.GetTree()
	require.NoError(t, err)

	proofAtIndices := []int{8, 9, 13}

	multiProof, err := objectTree.ProveMulti(proofAtIndices)
	require.NoError(t, err)
	ok, err := ssz.VerifyMultiproof(objectTree.Hash(), multiProof.Hashes, multiProof.Leaves, proofAtIndices)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestBeaconState_BlockRootAtIndexProof(t *testing.T) {
	data, err := os.ReadFile(TestFileName)
	require.NoError(t, err)

	sszState := BeaconStateBellatrix{}
	err = sszState.UnmarshalSSZ(data)
	require.NoError(t, err)

	// index of first block_root field in the beacon state
	leavesStart := 303104
	// let's prove block roof at position 4 in the block roots array
	index := leavesStart + 3

	expectedLeaf := sszState.BlockRoots[3]

	tree, err := sszState.GetTree()
	require.NoError(t, err)

	proof, err := tree.Prove(index)
	require.NoError(t, err)

	// check that the block root hash at the index matches what is in the beacon state
	require.Equal(t, expectedLeaf, proof.Leaf)

	root, err := sszState.HashTreeRoot()
	require.NoError(t, err)

	ok, err := ssz.VerifyProof(root[:], proof)
	require.NoError(t, err, "failed to verify proof")
	require.True(t, ok, "incorrect proof verification")
}

func TestBeaconState_BlockRootsProof(t *testing.T) {
	data, err := os.ReadFile(TestFileName)
	require.NoError(t, err)

	sszState := BeaconStateBellatrix{}
	err = sszState.UnmarshalSSZ(data)
	require.NoError(t, err)

	index := 37

	tree, err := sszState.GetTree()
	require.NoError(t, err)

	root, err := sszState.HashTreeRoot()
	require.NoError(t, err)

	// This is required to set the node values as the tree is hashed. Ideally should be done as part of GetTree() or Prove()
	tree.Hash()

	proof, err := tree.Prove(index)
	require.NoError(t, err)

	ok, err := ssz.VerifyProof(root[:], proof)
	require.NoError(t, err, "failed to verify proof")
	require.True(t, ok, "incorrect proof verification")
}

func TestBeaconStateTree_HashTreeRoot(t *testing.T) {
	data, err := os.ReadFile(TestFileName)
	require.NoError(t, err)

	sszState := BeaconStateBellatrix{}
	err = sszState.UnmarshalSSZ(data)
	require.NoError(t, err)

	tree, err := sszState.GetTree()
	require.NoError(t, err)

	hash := tree.Hash()

	// taken from https://goerli.beaconcha.in/slot/4744352 - stateRoot field
	require.Equal(t, "c4a9c5ebf637c089db599574b568bb679b385c1984f08410707db08e03d7ae52", hex.EncodeToString(hash))
}
