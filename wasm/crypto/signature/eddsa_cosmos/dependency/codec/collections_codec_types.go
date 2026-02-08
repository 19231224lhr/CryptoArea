package codec

import "errors"

var ErrEncoding = errors.New("collections: encoding error")

type KeyCodec[T any] interface {
	Encode(buffer []byte, key T) (int, error)
	Decode(buffer []byte) (int, T, error)
	Size(key T) int
	EncodeJSON(value T) ([]byte, error)
	DecodeJSON(b []byte) (T, error)
	Stringify(key T) string
	KeyType() string

	EncodeNonTerminal(buffer []byte, key T) (int, error)
	DecodeNonTerminal(buffer []byte) (int, T, error)
	SizeNonTerminal(key T) int
}

type ValueCodec[T any] interface {
	Encode(value T) ([]byte, error)
	Decode(b []byte) (T, error)
	EncodeJSON(value T) ([]byte, error)
	DecodeJSON(b []byte) (T, error)
	Stringify(value T) string
	ValueType() string
}
