package varsig

import (
	"encoding/binary"
	"fmt"
)

// Prefix is the value for the varsig's varuint prefix byte.
const Prefix = uint64(0x34)

// Hash is the value that specifies the hash algorithm
// that's used to reduce the signed content
type Hash uint64

// Constant values that allow Varsig implementations to specify how
// the payload content is hashed before the signature is generated.
const (
	HashUnspecified Hash = 0x00

	HashSha2_224 = Hash(0x1013)
	HashSha2_256 = Hash(0x12)
	HashSha2_384 = Hash(0x20)
	HashSha2_512 = Hash(0x13)

	HashSha3_224 = Hash(0x17)
	HashSha3_256 = Hash(0x16)
	HashSha3_384 = Hash(0x15)
	HashSha3_512 = Hash(0x14)

	HashSha512_224 = Hash(0x1014)
	HashSha512_256 = Hash(0x1015)

	HashBlake2s_256 = Hash(0xb260)
	HashBlake2b_256 = Hash(0xb220)
	HashBlake2b_384 = Hash(0xb230)
	HashBlake2b_512 = Hash(0xb240)

	HashShake_256 = Hash(0x19)

	HashKeccak256 = Hash(0x1b)
	HashKeccak512 = Hash(0x1d)
)

// DecodeHashAlgorithm reads and validates the expected hash algorithm
// (for varsig types include a variable hash algorithm.)
func DecodeHashAlgorithm(r BytesReader) (Hash, error) {
	u, err := binary.ReadUvarint(r)
	if err != nil {
		return HashUnspecified, fmt.Errorf("%w: %w", ErrUnknownHash, err)
	}

	h := Hash(u)

	switch h {
	case HashSha2_224,
		HashSha2_256,
		HashSha2_384,
		HashSha2_512,
		HashSha3_224,
		HashSha3_256,
		HashSha3_384,
		HashSha3_512,
		HashSha512_224,
		HashSha512_256,
		HashBlake2s_256,
		HashBlake2b_256,
		HashBlake2b_384,
		HashBlake2b_512,
		HashShake_256,
		HashKeccak256,
		HashKeccak512:
		return h, nil
	default:
		return HashUnspecified, fmt.Errorf("%w: %x", ErrUnknownHash, h)
	}
}

// PayloadEncoding specifies the encoding of the data being (hashed and)
// signed.  A canonical representation of the data is required to produce
// consistent hashes and signatures.
type PayloadEncoding int

// Constant values that allow Varsig implementations to specify how the
// payload content is encoded before being hashed.
// In varsig >= v1, only canonical encoding is allowed.
const (
	PayloadEncodingUnspecified = PayloadEncoding(iota)
	PayloadEncodingVerbatim
	PayloadEncodingDAGPB
	PayloadEncodingDAGCBOR
	PayloadEncodingDAGJSON
	PayloadEncodingEIP191Raw
	PayloadEncodingEIP191Cbor
	PayloadEncodingJWT
)

const (
	encodingSegmentVerbatim = uint64(0x5f)
	encodingSegmentDAGPB    = uint64(0x70)
	encodingSegmentDAGCBOR  = uint64(0x71)
	encodingSegmentDAGJSON  = uint64(0x0129)
	encodingSegmentEIP191   = uint64(0xe191)
	encodingSegmentJWT      = uint64(0x6a77)
)

// DecodePayloadEncoding reads and validates the expected canonical payload
// encoding of the data to be signed.
func DecodePayloadEncoding(r BytesReader, vers Version) (PayloadEncoding, error) {
	seg1, err := binary.ReadUvarint(r)
	if err != nil {
		return PayloadEncodingUnspecified, fmt.Errorf("%w: %w", ErrUnsupportedPayloadEncoding, err)
	}

	switch vers {
	case Version0:
		switch seg1 {
		case encodingSegmentVerbatim:
			return PayloadEncodingVerbatim, nil
		case encodingSegmentDAGPB:
			return PayloadEncodingDAGPB, nil
		case encodingSegmentDAGCBOR:
			return PayloadEncodingDAGCBOR, nil
		case encodingSegmentDAGJSON:
			return PayloadEncodingDAGJSON, nil
		case encodingSegmentEIP191:
			seg2, err := binary.ReadUvarint(r)
			if err != nil {
				return PayloadEncodingUnspecified, fmt.Errorf("%w: incomplete EIP191 encoding: %w", ErrUnsupportedPayloadEncoding, err)
			}
			switch seg2 {
			case encodingSegmentVerbatim:
				return PayloadEncodingEIP191Raw, nil
			case encodingSegmentDAGCBOR:
				return PayloadEncodingEIP191Cbor, nil
			default:
				return PayloadEncodingUnspecified, fmt.Errorf("%w: version=%d, encoding=%x+%x", ErrUnsupportedPayloadEncoding, vers, seg1, seg2)
			}
		case encodingSegmentJWT:
			return PayloadEncodingJWT, nil
		default:
			return PayloadEncodingUnspecified, fmt.Errorf("%w: version=%d, encoding=%x", ErrUnsupportedPayloadEncoding, vers, seg1)
		}
	case Version1:
		switch seg1 {
		case encodingSegmentVerbatim:
			return PayloadEncodingVerbatim, nil
		case encodingSegmentDAGCBOR:
			return PayloadEncodingDAGCBOR, nil
		case encodingSegmentDAGJSON:
			return PayloadEncodingDAGJSON, nil
		case encodingSegmentEIP191:
			seg2, err := binary.ReadUvarint(r)
			if err != nil {
				return PayloadEncodingUnspecified, fmt.Errorf("%w: incomplete EIP191 encoding: %w", ErrUnsupportedPayloadEncoding, err)
			}
			switch seg2 {
			case encodingSegmentVerbatim:
				return PayloadEncodingEIP191Raw, nil
			case encodingSegmentDAGCBOR:
				return PayloadEncodingEIP191Cbor, nil
			default:
				return PayloadEncodingUnspecified, fmt.Errorf("%w: version=%d, encoding=%x+%x", ErrUnsupportedPayloadEncoding, vers, seg1, seg2)
			}
		default:
			return PayloadEncodingUnspecified, fmt.Errorf("%w: version=%d, encoding=%x", ErrUnsupportedPayloadEncoding, vers, seg1)
		}
	default:
		return 0, ErrUnsupportedVersion
	}
}

// EncodePayloadEncoding returns the PayloadEncoding as serialized bytes.
// If enc is not a valid PayloadEncoding, this function will panic.
func EncodePayloadEncoding(enc PayloadEncoding) []byte {
	res := make([]byte, 0, 8)
	switch enc {
	case PayloadEncodingVerbatim:
		res = binary.AppendUvarint(res, encodingSegmentVerbatim)
	case PayloadEncodingDAGPB:
		res = binary.AppendUvarint(res, encodingSegmentDAGPB)
	case PayloadEncodingDAGCBOR:
		res = binary.AppendUvarint(res, encodingSegmentDAGCBOR)
	case PayloadEncodingDAGJSON:
		res = binary.AppendUvarint(res, encodingSegmentDAGJSON)
	case PayloadEncodingEIP191Raw:
		res = binary.AppendUvarint(res, encodingSegmentEIP191)
		res = binary.AppendUvarint(res, encodingSegmentVerbatim)
	case PayloadEncodingEIP191Cbor:
		res = binary.AppendUvarint(res, encodingSegmentEIP191)
		res = binary.AppendUvarint(res, encodingSegmentDAGCBOR)
	case PayloadEncodingJWT:
		res = binary.AppendUvarint(res, encodingSegmentJWT)
	default:
		panic(fmt.Sprintf("invalid encoding: %v", enc))
	}

	return res
}

// Discriminator is (usually) the value representing the public key type of
// the algorithm used to create the signature.
//
// There is no set list of constants here, nor is there a decode function
// as the author of an implementation should include the constant with the
// implementation, and the decoding is handled by the Handler, which uses
// the Discriminator to choose the correct implementation.  Also note that
// some of the Discriminator values for a specific implementation have
// changed between varsig v0 and v1, so it's possible to have more than one
// constant defined per implementation.
type Discriminator uint64
