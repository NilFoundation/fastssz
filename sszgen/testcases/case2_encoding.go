// Code generated by fastssz. DO NOT EDIT.
// Hash: 44566646e4c1498bce3271d6c03a9108bb4af48414b1d759c07e3572846863f1
// Version: 0.1.3
package testcases

import (
	ssz "github.com/NilFoundation/fastssz"
)

// MarshalSSZ ssz marshals the Case2A object
func (c *Case2A) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(c)
}

// MarshalSSZTo ssz marshals the Case2A object to a target array
func (c *Case2A) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf

	// Field (0) 'A'
	dst = ssz.MarshalUint64(dst, c.A)

	return
}

// UnmarshalSSZ ssz unmarshals the Case2A object
func (c *Case2A) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size != 8 {
		return ssz.ErrSize
	}

	// Field (0) 'A'
	c.A = ssz.UnmarshallUint64(buf[0:8])

	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the Case2A object
func (c *Case2A) SizeSSZ() (size int) {
	size = 8
	return
}

// HashTreeRoot ssz hashes the Case2A object
func (c *Case2A) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(c)
}

// HashTreeRootWith ssz hashes the Case2A object with a hasher
func (c *Case2A) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'A'
	hh.PutUint64(c.A)

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the Case2A object
func (c *Case2A) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(c)
}

// MarshalSSZ ssz marshals the Case2B object
func (c *Case2B) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(c)
}

// MarshalSSZTo ssz marshals the Case2B object to a target array
func (c *Case2B) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf

	// Field (0) 'A'
	dst = ssz.MarshalUint64(dst, c.A)

	// Field (1) 'B'
	dst = ssz.MarshalUint64(dst, c.B)

	return
}

// UnmarshalSSZ ssz unmarshals the Case2B object
func (c *Case2B) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size != 16 {
		return ssz.ErrSize
	}

	// Field (0) 'A'
	c.A = ssz.UnmarshallUint64(buf[0:8])

	// Field (1) 'B'
	c.B = ssz.UnmarshallUint64(buf[8:16])

	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the Case2B object
func (c *Case2B) SizeSSZ() (size int) {
	size = 16
	return
}

// HashTreeRoot ssz hashes the Case2B object
func (c *Case2B) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(c)
}

// HashTreeRootWith ssz hashes the Case2B object with a hasher
func (c *Case2B) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'A'
	hh.PutUint64(c.A)

	// Field (1) 'B'
	hh.PutUint64(c.B)

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the Case2B object
func (c *Case2B) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(c)
}
