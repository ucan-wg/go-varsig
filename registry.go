package varsig

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// Version represents which version of the varsig specification was used
// to produce Varsig value.
type Version uint64

// Constants for the existing varsig specifications
const (
	Version0 Version = 0
	Version1 Version = 1
)

// DecodeFunc is a function that parses the varsig representing a specific
// signing algorithm.
type DecodeFunc func(io.ByteReader) (Varsig, error)

// Registry contains a mapping between known signing algorithms and
// functions that can parse varsigs for that signing algorithm.
type Registry map[Algorithm]DecodeFunc

// DefaultRegistry provides a Registry containing the mappings for the
// signing algorithms which have an implementation within this library.
func DefaultRegistry() Registry {
	return map[Algorithm]DecodeFunc{
		AlgorithmRSA:   decodeRSA,
		AlgorithmEdDSA: decodeEdDSA,
		AlgorithmECDSA: decodeECDSA,
	}
}

// NewRegistry creates an empty Registry.
func NewRegistry() Registry {
	return make(Registry)
}

// Register allows new mappings between a signing algorithm and its parsing
// function to the Registry.
func (rs Registry) Register(alg Algorithm, decodeFunc DecodeFunc) {
	rs[alg] = decodeFunc
}

// Decode converts the provided data into one of the registered Varsig
// types.
func (rs Registry) Decode(data []byte) (Varsig, error) {
	return rs.DecodeStream(bytes.NewReader(data))
}

// DecodeStream converts data read from the provided io.Reader into one
// of the registered Varsig types.
func (rs Registry) DecodeStream(r io.ByteReader) (Varsig, error) {
	pre, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadPrefix, err)
	}

	if pre != Prefix {
		return nil, fmt.Errorf("%w: expected %d, got %d", ErrBadPrefix, Prefix, pre)
	}

	vers, algo, err := rs.decodeVersAndAlgo(r)
	if err != nil {
		return nil, err
	}

	if vers != Version1 {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedVersion, vers)
	}

	decodeFunc, ok := rs[Algorithm(algo)]
	if !ok {
		return nil, fmt.Errorf("%w: %x", ErrUnknownAlgorithm, algo)
	}

	return decodeFunc(r)
}

func (rs Registry) decodeVersAndAlgo(r io.ByteReader) (Version, Algorithm, error) {
	vers, err := binary.ReadUvarint(r)
	if err != nil {
		return Version(vers), 0, err
	}

	if vers > 1 && vers < 64 {
		return Version(vers), 0, fmt.Errorf("%w: %d", ErrUnsupportedVersion, vers)
	}

	if vers >= 64 {
		return 0, Algorithm(vers), nil
	}

	algo, err := binary.ReadUvarint(r)

	return Version(vers), Algorithm(algo), err
}
