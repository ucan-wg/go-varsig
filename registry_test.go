package varsig_test

import (
	"bytes"
	"encoding/hex"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ucan-wg/go-varsig"
)

func TestRegistry_Decode(t *testing.T) {
	t.Run("passes - v1", func(t *testing.T) {
		data, err := hex.DecodeString("34018120")
		require.NoError(t, err)

		reg := testRegistry(t)

		vs, err := reg.DecodeStream(bytes.NewReader(data))
		require.NoError(t, err)
		assert.Equal(t, varsig.Version1, vs.Version())
		assert.Equal(t, testAlgorithm1, vs.Algorithm())
	})
}

const (
	testAlgorithm0 varsig.Algorithm = 0x1000
	testAlgorithm1 varsig.Algorithm = 0x1001
)

func testRegistry(t *testing.T) varsig.Registry {
	t.Helper()

	reg := varsig.NewRegistry()
	reg.Register(testAlgorithm0, testDecodeFunc(testAlgorithm0))
	reg.Register(testAlgorithm1, testDecodeFunc(testAlgorithm1))

	return reg
}

func testDecodeFunc(algo varsig.Algorithm) varsig.DecodeFunc {
	return func(r io.ByteReader) (varsig.Varsig, error) {
		return &testVarsig{algo: algo}, nil
	}
}

var _ varsig.Varsig = testVarsig{}

type testVarsig struct {
	algo   varsig.Algorithm
	payEnc varsig.PayloadEncoding
}

func (v testVarsig) Version() varsig.Version {
	return varsig.Version1
}

func (v testVarsig) Algorithm() varsig.Algorithm {
	return v.algo
}

func (v testVarsig) Hash() varsig.Hash {
	return varsig.HashUnspecified
}

func (v testVarsig) PayloadEncoding() varsig.PayloadEncoding {
	return v.payEnc
}

func (v testVarsig) Encode() []byte {
	return nil
}
