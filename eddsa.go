package varsig

import (
	"encoding/binary"
	"fmt"
	"io"
)

// AlgorithmEdDSA is the value specifying an EdDSA signature.
const AlgorithmEdDSA = Algorithm(0xed)

// EdDSACurve are values that specify which Edwards curve is used when
// generating the signature.
type EdDSACurve uint64

// Constants describing the values for each specific Edwards curve that can
// be encoded into a Varsig.
const (
	CurveEd25519 = EdDSACurve(0xed)
	CurveEd448   = EdDSACurve(0x1203)
)

func decodeEdDSACurve(r io.ByteReader) (EdDSACurve, error) {
	u, err := binary.ReadUvarint(r)
	if err != nil {
		return 0, err
	}

	switch curve := EdDSACurve(u); curve {
	case CurveEd25519, CurveEd448:
		return curve, nil
	default:
		return 0, fmt.Errorf("%w: %x", ErrUnknownEdDSACurve, u)
	}
}

var _ Varsig = EdDSAVarsig{}

// EdDSAVarsig is a varsig that encodes the parameters required to describe
// an EdDSA signature.
type EdDSAVarsig struct {
	varsig

	curve   EdDSACurve
	hashAlg Hash
}

// NewEdDSAVarsig creates and validates an EdDSA varsig with the provided
// curve, hash algorithm and payload encoding.
func NewEdDSAVarsig(curve EdDSACurve, hashAlgorithm Hash, payloadEncoding PayloadEncoding) EdDSAVarsig {
	return EdDSAVarsig{
		varsig: varsig{
			algo:   AlgorithmEdDSA,
			payEnc: payloadEncoding,
		},
		curve:   curve,
		hashAlg: hashAlgorithm,
	}
}

// Curve returns the Edwards curve used to generate the EdDSA signature.
func (v EdDSAVarsig) Curve() EdDSACurve {
	return v.curve
}

// Hash returns the value describing the hash algorithm used to hash
// the payload content before the signature is generated.
func (v EdDSAVarsig) Hash() Hash {
	return v.hashAlg
}

// Encode returns the encoded byte format of the EdDSAVarsig.
func (v EdDSAVarsig) Encode() []byte {
	buf := v.encode()

	buf = binary.AppendUvarint(buf, uint64(v.curve))
	buf = binary.AppendUvarint(buf, uint64(v.hashAlg))
	buf = append(buf, EncodePayloadEncoding(v.payEnc)...)

	return buf
}

func decodeEdDSA(r io.ByteReader) (Varsig, error) {
	curve, err := decodeEdDSACurve(r)
	if err != nil {
		return nil, err
	}

	hashAlg, err := DecodeHashAlgorithm(r)
	if err != nil {
		return nil, err
	}

	payEnc, err := DecodePayloadEncoding(r)
	if err != nil {
		return nil, err
	}

	return NewEdDSAVarsig(curve, hashAlg, payEnc), nil
}
