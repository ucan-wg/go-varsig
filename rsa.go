package varsig

import (
	"encoding/binary"
	"io"
)

// AlgorithmRSA is the value specifying an RSA signature.
const AlgorithmRSA = Algorithm(0x1205)

var _ Varsig = RSAVarsig{}

// RSAVarsig is a varsig that encodes the parameters required to describe
// an RSA signature.
type RSAVarsig struct {
	varsig
	hashAlg Hash
	keyLen  uint64
}

// NewRSAVarsig creates and validates an RSA varsig with the provided
// hash algorithm, key length and payload encoding.
func NewRSAVarsig(hashAlgorithm Hash, keyLen uint64, payloadEncoding PayloadEncoding) RSAVarsig {
	return RSAVarsig{
		varsig: varsig{
			algo:   AlgorithmRSA,
			payEnc: payloadEncoding,
		},
		hashAlg: hashAlgorithm,
		keyLen:  keyLen,
	}
}

// Encode returns the encoded byte format of the RSAVarsig.
func (v RSAVarsig) Encode() []byte {
	buf := v.encode()

	buf = binary.AppendUvarint(buf, uint64(v.hashAlg))
	buf = binary.AppendUvarint(buf, v.keyLen)
	buf = append(buf, EncodePayloadEncoding(v.payEnc)...)

	return buf
}

// Hash returns the value describing the hash algorithm used to hash
// the payload content before the signature is generated.
func (v RSAVarsig) Hash() Hash {
	return v.hashAlg
}

// KeyLength returns the length of the RSA key used to sign the payload
// content.
func (v RSAVarsig) KeyLength() uint64 {
	return v.keyLen
}

func decodeRSA(r io.ByteReader) (Varsig, error) {
	hashAlg, err := DecodeHashAlgorithm(r)
	if err != nil {
		return nil, err
	}

	keyLen, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}

	payEnc, err := DecodePayloadEncoding(r)
	if err != nil {
		return nil, err
	}

	return NewRSAVarsig(hashAlg, keyLen, payEnc), nil
}
