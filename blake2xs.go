package blake2xs

import (
	"errors"
	"hash"
	"io"

	"github.com/dchest/blake2s"
)

// UnknownSize is used when the output size of XOF is unknown beforehand. It
// can be used to read as many bytes as required from the XOF up to its value.
// For unknown output size, shorter outputs are prefixes of longer outputs.
const UnknownSize = 1<<16 - 1

// Config is used to configure hash function parameters and keying.
// All parameters are optional.
type Config struct {
	Size   uint16        // digest size (if zero, size is UnknownSize)
	Key    []byte        // key for prefix-MAC
	Salt   []byte        // salt (if < 8 bytes, padded with zeros)
	Person []byte        // personalization (if < 8 bytes, padded with zeros)
	Tree   *blake2s.Tree // parameters for tree hashing
}

type xof struct {
	rh   hash.Hash          // root hash instance
	oc   blake2s.Config     // output config
	h0   []byte             // root hash digest, nil if not finalized yet
	x    [blake2s.Size]byte // buffer for output
	px   int                // position in output buffer
	left int                // number of output bytes left to generate
}

// NewXOF returns a new extended output function.
func NewXOF(c *Config) (io.ReadWriter, error) {
	outSize := int(c.Size)
	if outSize == 0 {
		outSize = UnknownSize
	}

	// Create root hash config.
	rc := blake2s.Config{
		Size:   blake2s.Size,
		Key:    c.Key,
		Salt:   c.Salt,
		Person: c.Person,
		Tree:   c.Tree,
	}

	if rc.Tree == nil {
		rc.Tree = &blake2s.Tree{
			Fanout:   1,
			MaxDepth: 1,
		}
	}
	rc.Tree.NodeOffset += uint64(outSize) << 32

	// Create initial config for output hashes.
	oc := blake2s.Config{
		Size:   blake2s.Size,
		Salt:   c.Salt,
		Person: c.Person,
		Tree: &blake2s.Tree{
			Fanout:        0,
			MaxDepth:      0,
			LeafSize:      blake2s.Size,
			NodeOffset:    uint64(outSize) << 32,
			NodeDepth:     0,
			InnerHashSize: blake2s.Size,
			IsLastNode:    false,
		},
	}

	rh, err := blake2s.New(&rc)
	if err != nil {
		return nil, err
	}

	return &xof{
		rh:   rh,
		oc:   oc,
		px:   blake2s.Size, // set to digest size
		left: outSize,
	}, nil
}

func (x *xof) Write(p []byte) (nn int, err error) {
	if x.h0 != nil {
		return 0, errors.New("blake2xs: cannot write after reading")
	}
	return x.rh.Write(p)
}

func (x *xof) Read(p []byte) (nn int, err error) {
	if x.h0 == nil {
		// Get root digest
		x.h0 = x.rh.Sum(nil)
	}
	for i := range p {
		if x.left == 0 && i != len(p) {
			return nn, io.EOF
		}
		if x.px >= blake2s.Size {
			// Refill buffer.
			if x.left < blake2s.Size {
				// This is the last block.
				x.oc.Size = uint8(x.left)
			}
			h, err := blake2s.New(&x.oc)
			if err != nil {
				return nn, err
			}
			h.Write(x.h0)
			h.Sum(x.x[:0])
			x.oc.Tree.NodeOffset++
			x.px = 0
		}
		p[i] = x.x[x.px]
		x.px++
		x.left--
		nn++
	}
	return nn, err
}
