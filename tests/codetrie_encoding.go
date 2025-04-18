// Code generated by fastssz. DO NOT EDIT.
// Hash: df8ee20c084275038d70ba95d464efb07c8cdbd9bbc7ff4cf7d9f52ebad035db
// Version: 0.1.3
package tests

import (
	ssz "github.com/NilFoundation/fastssz"
)

// MarshalSSZ ssz marshals the Metadata object
func (m *Metadata) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(m)
}

// MarshalSSZTo ssz marshals the Metadata object to a target array
func (m *Metadata) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf

	// Field (0) 'Version'
	dst = ssz.MarshalUint8(dst, m.Version)

	// Field (1) 'CodeHash'
	if size := len(m.CodeHash); size != 32 {
		err = ssz.ErrBytesLengthFn("Metadata.CodeHash", size, 32)
		return
	}
	dst = append(dst, m.CodeHash...)

	// Field (2) 'CodeLength'
	dst = ssz.MarshalUint16(dst, m.CodeLength)

	return
}

// UnmarshalSSZ ssz unmarshals the Metadata object
func (m *Metadata) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size != 35 {
		return ssz.ErrSize
	}

	// Field (0) 'Version'
	m.Version = ssz.UnmarshallUint8(buf[0:1])

	// Field (1) 'CodeHash'
	if cap(m.CodeHash) == 0 {
		m.CodeHash = make([]byte, 0, len(buf[1:33]))
	}
	m.CodeHash = append(m.CodeHash, buf[1:33]...)

	// Field (2) 'CodeLength'
	m.CodeLength = ssz.UnmarshallUint16(buf[33:35])

	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the Metadata object
func (m *Metadata) SizeSSZ() (size int) {
	size = 35
	return
}

// HashTreeRoot ssz hashes the Metadata object
func (m *Metadata) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(m)
}

// HashTreeRootWith ssz hashes the Metadata object with a hasher
func (m *Metadata) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'Version'
	hh.PutUint8(m.Version)

	// Field (1) 'CodeHash'
	if size := len(m.CodeHash); size != 32 {
		err = ssz.ErrBytesLengthFn("Metadata.CodeHash", size, 32)
		return
	}
	hh.PutBytes(m.CodeHash)

	// Field (2) 'CodeLength'
	hh.PutUint16(m.CodeLength)

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the Metadata object
func (m *Metadata) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(m)
}

// MarshalSSZ ssz marshals the Chunk object
func (c *Chunk) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(c)
}

// MarshalSSZTo ssz marshals the Chunk object to a target array
func (c *Chunk) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf

	// Field (0) 'FIO'
	dst = ssz.MarshalUint8(dst, c.FIO)

	// Field (1) 'Code'
	if size := len(c.Code); size != 32 {
		err = ssz.ErrBytesLengthFn("Chunk.Code", size, 32)
		return
	}
	dst = append(dst, c.Code...)

	return
}

// UnmarshalSSZ ssz unmarshals the Chunk object
func (c *Chunk) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size != 33 {
		return ssz.ErrSize
	}

	// Field (0) 'FIO'
	c.FIO = ssz.UnmarshallUint8(buf[0:1])

	// Field (1) 'Code'
	if cap(c.Code) == 0 {
		c.Code = make([]byte, 0, len(buf[1:33]))
	}
	c.Code = append(c.Code, buf[1:33]...)

	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the Chunk object
func (c *Chunk) SizeSSZ() (size int) {
	size = 33
	return
}

// HashTreeRoot ssz hashes the Chunk object
func (c *Chunk) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(c)
}

// HashTreeRootWith ssz hashes the Chunk object with a hasher
func (c *Chunk) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'FIO'
	hh.PutUint8(c.FIO)

	// Field (1) 'Code'
	if size := len(c.Code); size != 32 {
		err = ssz.ErrBytesLengthFn("Chunk.Code", size, 32)
		return
	}
	hh.PutBytes(c.Code)

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the Chunk object
func (c *Chunk) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(c)
}

// MarshalSSZ ssz marshals the CodeTrieSmall object
func (c *CodeTrieSmall) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(c)
}

// MarshalSSZTo ssz marshals the CodeTrieSmall object to a target array
func (c *CodeTrieSmall) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	offset := int(39)

	// Field (0) 'Metadata'
	if c.Metadata == nil {
		c.Metadata = new(Metadata)
	}
	if dst, err = c.Metadata.MarshalSSZTo(dst); err != nil {
		return
	}

	// Offset (1) 'Chunks'
	dst = ssz.WriteOffset(dst, offset)

	// Field (1) 'Chunks'
	if size := len(c.Chunks); size > 4 {
		err = ssz.ErrListTooBigFn("CodeTrieSmall.Chunks", size, 4)
		return
	}
	for ii := 0; ii < len(c.Chunks); ii++ {
		if dst, err = c.Chunks[ii].MarshalSSZTo(dst); err != nil {
			return
		}
	}

	return
}

// UnmarshalSSZ ssz unmarshals the CodeTrieSmall object
func (c *CodeTrieSmall) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 39 {
		return ssz.ErrSize
	}

	tail := buf
	var o1 uint64

	// Field (0) 'Metadata'
	if c.Metadata == nil {
		c.Metadata = new(Metadata)
	}
	if err = c.Metadata.UnmarshalSSZ(buf[0:35]); err != nil {
		return err
	}

	// Offset (1) 'Chunks'
	if o1 = ssz.ReadOffset(buf[35:39]); o1 > size {
		return ssz.ErrOffset
	}

	if o1 < 39 {
		return ssz.ErrInvalidVariableOffset
	}

	// Field (1) 'Chunks'
	{
		buf = tail[o1:]
		num, err := ssz.DivideInt2(len(buf), 33, 4)
		if err != nil {
			return err
		}
		c.Chunks = make([]*Chunk, num)
		for ii := 0; ii < num; ii++ {
			if c.Chunks[ii] == nil {
				c.Chunks[ii] = new(Chunk)
			}
			if err = c.Chunks[ii].UnmarshalSSZ(buf[ii*33 : (ii+1)*33]); err != nil {
				return err
			}
		}
	}
	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the CodeTrieSmall object
func (c *CodeTrieSmall) SizeSSZ() (size int) {
	size = 39

	// Field (1) 'Chunks'
	size += len(c.Chunks) * 33

	return
}

const CodeTrieSmallMaxChunksSize = 4

// HashTreeRoot ssz hashes the CodeTrieSmall object
func (c *CodeTrieSmall) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(c)
}

// HashTreeRootWith ssz hashes the CodeTrieSmall object with a hasher
func (c *CodeTrieSmall) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'Metadata'
	if c.Metadata == nil {
		c.Metadata = new(Metadata)
	}
	if err = c.Metadata.HashTreeRootWith(hh); err != nil {
		return
	}

	// Field (1) 'Chunks'
	{
		subIndx := hh.Index()
		num := uint64(len(c.Chunks))
		if num > 4 {
			err = ssz.ErrIncorrectListSize
			return
		}
		for _, elem := range c.Chunks {
			if err = elem.HashTreeRootWith(hh); err != nil {
				return
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, 4)
	}

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the CodeTrieSmall object
func (c *CodeTrieSmall) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(c)
}

// MarshalSSZ ssz marshals the CodeTrieBig object
func (c *CodeTrieBig) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(c)
}

// MarshalSSZTo ssz marshals the CodeTrieBig object to a target array
func (c *CodeTrieBig) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	offset := int(39)

	// Field (0) 'Metadata'
	if c.Metadata == nil {
		c.Metadata = new(Metadata)
	}
	if dst, err = c.Metadata.MarshalSSZTo(dst); err != nil {
		return
	}

	// Offset (1) 'Chunks'
	dst = ssz.WriteOffset(dst, offset)

	// Field (1) 'Chunks'
	if size := len(c.Chunks); size > 1024 {
		err = ssz.ErrListTooBigFn("CodeTrieBig.Chunks", size, 1024)
		return
	}
	for ii := 0; ii < len(c.Chunks); ii++ {
		if dst, err = c.Chunks[ii].MarshalSSZTo(dst); err != nil {
			return
		}
	}

	return
}

// UnmarshalSSZ ssz unmarshals the CodeTrieBig object
func (c *CodeTrieBig) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 39 {
		return ssz.ErrSize
	}

	tail := buf
	var o1 uint64

	// Field (0) 'Metadata'
	if c.Metadata == nil {
		c.Metadata = new(Metadata)
	}
	if err = c.Metadata.UnmarshalSSZ(buf[0:35]); err != nil {
		return err
	}

	// Offset (1) 'Chunks'
	if o1 = ssz.ReadOffset(buf[35:39]); o1 > size {
		return ssz.ErrOffset
	}

	if o1 < 39 {
		return ssz.ErrInvalidVariableOffset
	}

	// Field (1) 'Chunks'
	{
		buf = tail[o1:]
		num, err := ssz.DivideInt2(len(buf), 33, 1024)
		if err != nil {
			return err
		}
		c.Chunks = make([]*Chunk, num)
		for ii := 0; ii < num; ii++ {
			if c.Chunks[ii] == nil {
				c.Chunks[ii] = new(Chunk)
			}
			if err = c.Chunks[ii].UnmarshalSSZ(buf[ii*33 : (ii+1)*33]); err != nil {
				return err
			}
		}
	}
	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the CodeTrieBig object
func (c *CodeTrieBig) SizeSSZ() (size int) {
	size = 39

	// Field (1) 'Chunks'
	size += len(c.Chunks) * 33

	return
}

const CodeTrieBigMaxChunksSize = 1024

// HashTreeRoot ssz hashes the CodeTrieBig object
func (c *CodeTrieBig) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(c)
}

// HashTreeRootWith ssz hashes the CodeTrieBig object with a hasher
func (c *CodeTrieBig) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'Metadata'
	if c.Metadata == nil {
		c.Metadata = new(Metadata)
	}
	if err = c.Metadata.HashTreeRootWith(hh); err != nil {
		return
	}

	// Field (1) 'Chunks'
	{
		subIndx := hh.Index()
		num := uint64(len(c.Chunks))
		if num > 1024 {
			err = ssz.ErrIncorrectListSize
			return
		}
		for _, elem := range c.Chunks {
			if err = elem.HashTreeRootWith(hh); err != nil {
				return
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, 1024)
	}

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the CodeTrieBig object
func (c *CodeTrieBig) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(c)
}
