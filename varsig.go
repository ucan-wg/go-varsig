// Package varsig implements v1.0.0 of the [Varsig specification] with
// limited support for varsig < v1.  This is primarily in support of the
// UCAN v1.0.0 specification and will be deprecated in the future.
//
// # Common algorithm naming
//
// While there is no strict need for compatibility with JWA/JWT/JWE/JWS,
// all attempts are made to keep the algorithm names here consistent with
// list made available at the [IANA Registry] titled "JSON Web Signature
// and Encryption Algorithms" (JOSE.)
//
// It should also be noted that algorithm in this context might in fact be
// a pseudonym - for cryptographical signing algorithms that require the
// signed data to be hashed first, these names commonly refer to the
// combination of that signing algorithm and the hash algorithm.
//
// [IANA Registry]]: https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms
// [Varsig Specification]: https://github.com/ChainAgnostic/varsig
package varsig

import (
	"encoding/binary"
	"io"
)

// Varsig represents types that describe how a signature was generated
// and thus how to interpret the signature and verify the signed data.
type Varsig interface {
	// Version returns the varsig's version field.
	Version() Version

	// Algorithm returns the algorithm used to produce the corresponding signature.
	Algorithm() Algorithm

	// Hash returns the hash used on the data before signature.
	Hash() Hash

	// PayloadEncoding returns the codec that was used to encode the signed data.
	PayloadEncoding() PayloadEncoding

	// Encode returns the encoded byte format of the varsig.
	Encode() []byte
}

// Decode converts the provided data into one of the Varsig types
// provided by the DefaultRegistry.
func Decode(data []byte) (Varsig, error) {
	return DefaultRegistry().Decode(data)
}

// DecodeStream converts data read from the provided io.Reader into one
// of the Varsig types provided by the DefaultRegistry.
func DecodeStream(r io.ByteReader) (Varsig, error) {
	return DefaultRegistry().DecodeStream(r)
}

type varsig struct {
	algo   Algorithm
	payEnc PayloadEncoding
}

// Version returns the varsig's version field.
func (v varsig) Version() Version {
	return Version1
}

// Algorithm returns the algorithm used to produce the corresponding
// signature.
func (v varsig) Algorithm() Algorithm {
	return v.algo
}

// PayloadEncoding returns the codec that was used to encode the signed
// data.
func (v varsig) PayloadEncoding() PayloadEncoding {
	return v.payEnc
}

func (v varsig) encode() []byte {
	// Pre-allocate to the maximum size to avoid re-allocating.
	// I think the maximum is 10 bytes, but it's all the same for go to allocate 16 (due to the small
	// size allocation class), so we might as well get some headroom for bigger varints.
	buf := make([]byte, 0, 16)

	buf = binary.AppendUvarint(buf, Prefix)
	buf = binary.AppendUvarint(buf, uint64(Version1))
	buf = binary.AppendUvarint(buf, uint64(v.algo))

	return buf
}
