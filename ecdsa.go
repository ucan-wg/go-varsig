package varsig

import (
	"encoding/binary"
	"fmt"
	"io"
)

// AlgorithmECDSA is the value specifying an ECDSA signature.
const AlgorithmECDSA = Algorithm(0xec)

// ECDSACurve are values that specify which ECDSA curve is used when
// generating the signature.
type ECDSACurve uint64

// Constants describing the values for each specific ECDSA curve that can
// be encoded into a Varsig.
const (
	CurveSecp256k1 = ECDSACurve(0xe7)
	CurveP256      = ECDSACurve(0x1200)
	CurveP384      = ECDSACurve(0x1201)
	CurveP521      = ECDSACurve(0x1202)
)

func decodeECDSACurve(r io.ByteReader) (ECDSACurve, error) {
	u, err := binary.ReadUvarint(r)
	if err != nil {
		return 0, err
	}

	switch curve := ECDSACurve(u); curve {
	case CurveSecp256k1, CurveP256, CurveP384, CurveP521:
		return curve, nil
	default:
		return 0, fmt.Errorf("%w: %x", ErrUnknownECDSACurve, u)
	}
}

var _ Varsig = ECDSAVarsig{}

// ECDSAVarsig is a varsig that encodes the parameters required to describe
// an ECDSA signature.
type ECDSAVarsig struct {
	varsig

	curve   ECDSACurve
	hashAlg Hash
}

// NewECDSAVarsig creates and validates an ECDSA varsig with the provided
// curve, hash algorithm and payload encoding.
func NewECDSAVarsig(curve ECDSACurve, hashAlgorithm Hash, payloadEncoding PayloadEncoding) ECDSAVarsig {
	return ECDSAVarsig{
		varsig: varsig{
			algo:   AlgorithmECDSA,
			payEnc: payloadEncoding,
		},
		curve:   curve,
		hashAlg: hashAlgorithm,
	}
}

// Curve returns the elliptic curve used to generate the ECDSA signature.
func (v ECDSAVarsig) Curve() ECDSACurve {
	return v.curve
}

// Hash returns the value describing the hash algorithm used to hash
// the payload content before the signature is generated.
func (v ECDSAVarsig) Hash() Hash {
	return v.hashAlg
}

// Encode returns the encoded byte format of the ECDSAVarsig.
func (v ECDSAVarsig) Encode() []byte {
	buf := v.encode()

	buf = binary.AppendUvarint(buf, uint64(v.curve))
	buf = binary.AppendUvarint(buf, uint64(v.hashAlg))
	buf = append(buf, EncodePayloadEncoding(v.payEnc)...)

	return buf
}

func decodeECDSA(r io.ByteReader) (Varsig, error) {
	curve, err := decodeECDSACurve(r)
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

	return NewECDSAVarsig(curve, hashAlg, payEnc), nil
}
