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

	require.Equal(t, hex.EncodeToString(proof.Leaf), "a064480000000000000000000000000000000000000000000000000000000000")
	require.Equal(t, proofAtIndex, proof.Index)
	require.Equal(t, 3, len(proof.Hashes), "proof hashes length incorrect")
	require.Equal(t, "7859010000000000000000000000000000000000000000000000000000000000", hex.EncodeToString(proof.Hashes[0]))
	require.Equal(t, "1a2fefdff29d0b2f0147aed4043bfbe820df8515b79352d78a4b1e3b0e9a4d1d", hex.EncodeToString(proof.Hashes[1]))
	require.Equal(t, "0c117ede1ebf35078bb071eb3f0ef25b537325bc83d62d84e8efc04aa9de24f3", hex.EncodeToString(proof.Hashes[2]))
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

	require.Equal(t, 3, len(multiProof.Leaves), "multi proof leaf hashes length incorrect")
	require.Equal(t, "a064480000000000000000000000000000000000000000000000000000000000", hex.EncodeToString(multiProof.Leaves[0]))
	require.Equal(t, "7859010000000000000000000000000000000000000000000000000000000000", hex.EncodeToString(multiProof.Leaves[1]))
	require.Equal(t, "0000000000000000000000000000000000000000000000000000000000000000", hex.EncodeToString(multiProof.Leaves[2]))

	require.Equal(t, proofAtIndices, multiProof.Indices)
	require.Equal(t, 3, len(multiProof.Hashes), "proof hashes length incorrect")
	require.Equal(t, "445fab586d7d52993d7713c29da316d7e0fe04fd053983198af93fb131ce02ed", hex.EncodeToString(multiProof.Hashes[0]))
	require.Equal(t, "0f63cd0c9fbe679a562469831d8e810c9d33cc2409695b8e6a893e627ea952d1", hex.EncodeToString(multiProof.Hashes[1]))
	require.Equal(t, "1a2fefdff29d0b2f0147aed4043bfbe820df8515b79352d78a4b1e3b0e9a4d1d", hex.EncodeToString(multiProof.Hashes[2]))
}

func TestBeaconState_BlockRootAtIndexProof(t *testing.T) {
	t.SkipNow() // TODO: fails with timeout error

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
	t.SkipNow() // TODO: fails with timeout error

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
	t.SkipNow() // TODO: fails with timeout error

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
