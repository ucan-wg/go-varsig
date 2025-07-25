package varsig_test

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ucan-wg/go-varsig"
)

func TestDecodeEd25519(t *testing.T) {
	t.Parallel()

	t.Run("passes - section 3 example - v0", func(t *testing.T) {
		// Original:  34ed01    1371ae3784f03f9ee1163382fa6efa73b0c31ecf58c899c836709303ba4621d1e6df20e09aaa568914290b7ea124f5b38e70b9b69c7de0d216880eac885edd41c302
		// Corrected: 34ed011371ae3784f03f9ee1163382fa6efa73b0c31ecf58c899c836709303ba4621d1e6df20e09aaa568914290b7ea124f5b38e70b9b69c7de0d216880eac885edd41c302")

		hdr, err := hex.DecodeString("34ed011371")
		require.NoError(t, err)

		sig, err := hex.DecodeString("ae3784f03f9ee1163382fa6efa73b0c31ecf58c899c836709303ba4621d1e6df20e09aaa568914290b7ea124f5b38e70b9b69c7de0d216880eac885edd41c302")
		require.NoError(t, err)
		require.Len(t, sig, 64)

		t.Run("Decode", func(t *testing.T) {
			t.Parallel()

			v, err := varsig.Decode(append(hdr, sig...))
			require.NoError(t, err)
			require.NotNil(t, v)
			assert.Equal(t, varsig.Version0, v.Version())
			assert.Equal(t, varsig.DiscriminatorEdDSA, v.Discriminator())
			assert.Equal(t, varsig.PayloadEncodingDAGCBOR, v.PayloadEncoding())
			assert.Len(t, v.Signature(), 64)

			impl, ok := v.(varsig.EdDSAVarsig)
			require.True(t, ok)
			assert.Equal(t, varsig.CurveEd25519, impl.Curve())
			assert.Equal(t, varsig.HashSha2_512, impl.Hash())
		})

		t.Run("Encode", func(t *testing.T) {
			t.Parallel()

			v, err := varsig.NewEdDSAVarsig(
				varsig.CurveEd25519,
				varsig.HashSha2_512,
				varsig.PayloadEncodingDAGCBOR,
				varsig.WithForceVersion0(sig),
			)
			require.NoError(t, err)
			require.NotNil(t, v)
			assert.Equal(t, append(hdr, sig...), v.Encode())
		})
	})
}

func TestUCANExampleV1(t *testing.T) {
	t.Parallel()

	// This test is the value shown in the UCAN v1.0.0 example, which is
	// an EdDSA varsig = v1 with the Ed25519 curve, SHA2_256 hashing and
	// DAG-CBOR content encoding.
	example, err := base64.RawStdEncoding.DecodeString("NAHtAe0BE3E")
	require.NoError(t, err)

	t.Run("Decode", func(t *testing.T) {
		t.Parallel()

		v, err := varsig.Decode(example)
		require.NoError(t, err)

		ed25519V, ok := v.(varsig.EdDSAVarsig)
		require.True(t, ok)

		assert.Equal(t, varsig.Version1, ed25519V.Version())
		assert.Equal(t, varsig.DiscriminatorEdDSA, ed25519V.Discriminator())
		assert.Equal(t, varsig.CurveEd25519, ed25519V.Curve())
		assert.Equal(t, varsig.HashSha2_512, ed25519V.Hash())
		assert.Equal(t, varsig.PayloadEncodingDAGCBOR, ed25519V.PayloadEncoding())
		assert.Len(t, ed25519V.Signature(), 0)
	})

	t.Run("Encode", func(t *testing.T) {
		t.Parallel()

		edDSAVarsig, err := varsig.NewEdDSAVarsig(
			varsig.CurveEd25519,
			varsig.HashSha2_512,
			varsig.PayloadEncodingDAGCBOR,
		)
		require.NoError(t, err)

		assert.Equal(t, example, edDSAVarsig.Encode())
		t.Log(base64.RawStdEncoding.EncodeToString(edDSAVarsig.Encode()))
	})
}
