package testcases

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUint(t *testing.T) {
	s := Uints{
		Uint8:  Uint8(123),
		Uint16: Uint16(12345),
		Uint32: Uint32(1234567890),
		Uint64: Uint64(123456789000),
	}
	expectedHash := [32]byte{
		0x10, 0x3d, 0xe1, 0x91, 0x94, 0x1c, 0x95, 0xeb,
		0x2e, 0xef, 0x52, 0x6c, 0x7c, 0x87, 0x24, 0xc4,
		0xb0, 0x8d, 0x72, 0x2, 0x24, 0x3b, 0xf3, 0xe2,
		0x96, 0xba, 0xc5, 0x7d, 0xed, 0x89, 0x6a, 0x78,
	}

	bytes, err := s.MarshalSSZ()
	assert.NoError(t, err)

	var s2 Uints
	err = s2.UnmarshalSSZ(bytes)
	assert.NoError(t, err)

	assert.Equal(t, s, s2)

	h, err := s.HashTreeRoot()
	assert.NoError(t, err)

	assert.Equal(t, expectedHash, h)
}
