package ssz

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTreeFromChunks(t *testing.T) {
	chunks := [][]byte{
		{0x01, 0x01},
		{0x02, 0x02},
		{0x03, 0x03},
		{0x00, 0x00},
	}

	r, err := TreeFromChunks(chunks)
	if err != nil {
		t.Errorf("Failed to construct tree: %v\n", err)
	}
	for i := 4; i < 8; i++ {
		l, err := r.Get(i)
		if err != nil {
			t.Errorf("Failed getting leaf: %v\n", err)
		}
		if !bytes.Equal(l.value, chunks[i-4]) {
			t.Errorf("Incorrect leaf at index %d\n", i)
		}
	}
}

func TestParseTree(t *testing.T) {
	chunk1, err := hex.DecodeString("9a4aaa9f8c50cdb565a05ed94a0019cbea56349bdb4c5b639a26bcfed855c790")
	require.NoError(t, err)
	chunk2, err := hex.DecodeString("632a7e04caca67eed732cd670409acf2daaf88aed3977689446ba6f7d3e43aa4")
	require.NoError(t, err)
	chunk3, err := hex.DecodeString("6314fea8253a30f23d5af34b0b2e675d4c0d475e4f66e4392c535f2ca5c3ae32")
	require.NoError(t, err)

	chunks := [][]byte{chunk1, chunk2, chunk3}

	nodes := []*Node{}
	for _, chunk := range chunks {
		nodes = append(nodes, LeafFromBytes(chunk[:]))
	}

	r, err := TreeFromNodesWithMixin(nodes, len(nodes), 8)
	require.NoError(t, err, "failed to construct tree")
	require.Equal(t, "288d15af569f7da3abace0746f6d158790777a3d3da8d34f62c396dd39457ec9", hex.EncodeToString(r.Hash()))
}

func TestSparseTreeWithLeavesWithOtherNodes(t *testing.T) {
	valueIndex2, err := hex.DecodeString("452a7e04caca67eed732cd670409acf2daaf88aed3977689446ba6f7d3e43aa4")
	require.NoError(t, err)
	valueIndex3, err := hex.DecodeString("ef2a7e04caca67eed732cd670409acf2daaf88aed3977689446ba6f7d3e43aa4")
	require.NoError(t, err)
	valueIndex4, err := hex.DecodeString("842a7e04caca67eed732cd670409acf2daaf88aed3977689446ba6f7d3e43aa4")
	require.NoError(t, err)
	valueIndex5, err := hex.DecodeString("722a7e04caca67eed732cd670409acf2daaf88aed3977689446ba6f7d3e43aa4")
	require.NoError(t, err)
	valueIndex6, err := hex.DecodeString("982a7e04caca67eed732cd670409acf2daaf88aed3977689446ba6f7d3e43aa4")
	require.NoError(t, err)
	valueIndex7, err := hex.DecodeString("632a7e04caca67eed732cd670409acf2daaf88aed3977689446ba6f7d3e43aa4")
	require.NoError(t, err)

	nodes := []*Node{
		{
			left: &Node{
				value: valueIndex2,
			},
			right: &Node{
				value: valueIndex3,
			},
		},
		{
			left: &Node{
				value: valueIndex4,
			},
			right: &Node{
				value: valueIndex5,
			},
		},
		{
			left: &Node{
				value: valueIndex6,
			},
			right: &Node{
				value: valueIndex7,
			},
		},
	}

	limit := 8

	r, err := TreeFromNodesWithMixin(nodes, len(nodes), limit)
	require.NoError(t, err, "failed to construct tree")
	require.Equal(t, "05e311d40ed6adf20ec7e2e060bc8b973e34bae9c395985ebfaeab6e213df47c", hex.EncodeToString(r.Hash()))
}

func TestHashTree(t *testing.T) {
	expectedRootHex := "27b4eb60243abfad5a1fa54297c648deab5e59f4cc0bf4fe5b5fd4b5ebcc1fff"
	expectedRoot, err := hex.DecodeString(expectedRootHex)
	if err != nil {
		t.Errorf("Failed to decode hex string\n")
	}

	chunks := [][]byte{
		{0x01, 0x01},
		{0x02, 0x02},
		{0x03, 0x03},
		{0x00, 0x00},
	}

	r, err := TreeFromChunks(chunks)
	if err != nil {
		t.Errorf("Failed to construct tree: %v\n", err)
	}

	h := r.Hash()
	if !bytes.Equal(h, expectedRoot) {
		t.Errorf("Computed hash is incorrect. Expected %s, got %s\n", expectedRootHex, hex.EncodeToString(h))
	}
}

func TestProve(t *testing.T) {
	expectedProofHex := []string{
		"0000",
		"2070f76b0e97b1f7502311cc07a7da947a94ec15d7f8a25b7fcaa9177101513b",
	}
	chunks := [][]byte{
		{0x01, 0x01},
		{0x02, 0x02},
		{0x03, 0x03},
		{0x00, 0x00},
	}

	r, err := TreeFromChunks(chunks)
	if err != nil {
		t.Errorf("Failed to construct tree: %v\n", err)
	}

	p, err := r.Prove(6)
	if err != nil {
		t.Errorf("Failed to generate proof: %v\n", err)
	}

	if p.Index != 6 {
		t.Errorf("Proof has invalid index. Expected %d, got %d\n", 6, p.Index)
	}
	if !bytes.Equal(p.Leaf, chunks[2]) {
		t.Errorf("Proof has invalid leaf. Expected %v, got %v\n", chunks[2], p.Leaf)
	}
	if len(p.Hashes) != len(expectedProofHex) {
		t.Errorf("Proof has invalid length. Expected %d, got %d\n", len(expectedProofHex), len(p.Hashes))
	}

	for i, n := range p.Hashes {
		e, err := hex.DecodeString(expectedProofHex[i])
		if err != nil {
			t.Errorf("Failed to decode hex string: %v\n", err)
		}
		if !bytes.Equal(e, n) {
			t.Errorf("Invalid proof item. Expected %s, got %s\n", expectedProofHex[i], hex.EncodeToString(n))
		}
	}
}

func TestProveMulti(t *testing.T) {
	chunks := [][]byte{
		{0x01, 0x01},
		{0x02, 0x02},
		{0x03, 0x03},
		{0x04, 0x04},
	}

	r, err := TreeFromChunks(chunks)
	if err != nil {
		t.Errorf("Failed to construct tree: %v\n", err)
	}

	p, err := r.ProveMulti([]int{6, 7})
	if err != nil {
		t.Errorf("Failed to generate proof: %v\n", err)
	}

	if len(p.Hashes) != 1 {
		t.Errorf("Incorrect number of hashes in proof. Expected 1, got %d\n", len(p.Hashes))
	}
}

func TestGetRequiredIndices(t *testing.T) {
	indices := []int{10, 48, 49}
	expected := []int{25, 13, 11, 7, 4}
	req := getRequiredIndices(indices)
	if len(expected) != len(req) {
		t.Fatalf("Required indices has wrong length. Expected %d, got %d\n", len(expected), len(req))
	}
	for i, r := range req {
		if r != expected[i] {
			t.Errorf("Invalid required index. Expected %d, got %d\n", expected[i], r)
		}
	}
}

func TestProveRepeated(t *testing.T) {
	expectedProofHex := []string{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0f63cd0c9fbe679a562469831d8e810c9d33cc2409695b8e6a893e627ea952d1",
		"2002fe39e9f175512f30e30fa0d4e003e9df611db3fca96197db976f8644c75a",
		"0efb0ee9dcc58a77f39d41bae90162cd3bf08e13a071178e1025553db53745ad",
		"27f5f069f3f41c239e75979eb0657fb075dbf942cca053299352f44b9e9965d3",
		"1fbd18a35a88359c8c07f8376be954c34dd26072ccf177877212c3f9374ddc59",
		"2e26d40034abf56520b6f5541568a7686ceb239e7758be6e532795b7f73fa5d2",
		"0b79992a65a374bac4b18ec26f9e37157d4e0f4c127c04ca72c8a53c41cd9224",
		"1bb420fa5409ee48bb27b0d4465592ab5707eddb0781c13558a4f0c897174603",
		"0324443b152adfd89fd6e9ab1f961f7d7a7685eda90ab43ac09b2032e749cbc2",
		"1c00cb3774bc70cc022ef9fde08ae772f60bd3a2687dc38a00aae29b24d69462",
		"25cf3992c3326fcdefb83c2be615934d83d7442ef45986cfa6c3232e7df3c9c8",
		"154c56140e60983aaa84422e1dc1157108ba78e67a2873b2be2fd0f4f40dc1ee",
		"12e3145a126ae9f763558b70a5f8028ee3df4621c0aabc84ef9343386c7eb13e",
		"2262efd8de5e475e56f5d15032313fd423a3d11b977e7937189f238da081cfd4",
		"14bc25b6b80519138cbf24ea6a9fb50c6de5866b597e1aab72546efd1693424e",
		"0221f72ccd94b863552b04add6c4e598e0b8ba417c1cc162aa3ea5c45de413c2",
		"13f6e36d3fdf2cc8d464d8fb7938ed1f4d0341f0bbac5547e1c00df112844350",
		"0dd210443855682a4b32995f498f365e4d2ba82936045b1611f80000a30d2580",
		"30177faa30b66f174c9c248aa8296d216b3a494430693a0d5ad71996c57996ad",
	}

	chunks := make([][]byte, 1048576)
	for i := uint32(0); i < 1048576; i++ {
		x := make([]byte, 4)
		binary.LittleEndian.PutUint32(x, i)
		chunks = append(chunks, x)
	}

	r, err := TreeFromChunks(chunks)
	if err != nil {
		t.Errorf("Failed to construct tree: %v\n", err)
		t.Fail()
	}

	// Repeatedly prove the same entry, to ensure that there are no mutations
	// as a result of proving.
	for i := 0; i < 1024; i++ {
		p, err := r.Prove(1048576)
		if err != nil {
			t.Errorf("Failed to generate proof: %v\n", err)
			t.Fail()
		}

		for i, n := range p.Hashes {
			e, err := hex.DecodeString(expectedProofHex[i])
			if err != nil {
				t.Errorf("Failed to decode hex string: %v\n", err)
				t.Fail()
			}
			if !bytes.Equal(e, n) {
				t.Errorf("Invalid proof item. Expected %s, got %s\n", expectedProofHex[i], hex.EncodeToString(n))
				t.Fail()
			}
		}
	}
}

func BenchmarkProve(b *testing.B) {
	chunks := make([][]byte, 1048576)
	for i := uint32(0); i < 1048576; i++ {
		x := make([]byte, 4)
		binary.LittleEndian.PutUint32(x, i)
		chunks = append(chunks, x)
	}

	r, err := TreeFromChunks(chunks)
	if err != nil {
		b.Errorf("Failed to construct tree: %v\n", err)
		b.Fail()
	}

	for i := 0; i < b.N; i++ {
		//nolint
		_, err := r.Prove(rand.Intn(1048575) + 1)
		if err != nil {
			b.Errorf("Failed to generate proof: %v\n", err)
			b.Fail()
		}
	}
}
