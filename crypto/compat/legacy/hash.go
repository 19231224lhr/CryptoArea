package legacy

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
)

func SHA256Concat(key []byte, data []byte) []byte {
	combined := make([]byte, 0, len(key)+len(data))
	combined = append(combined, key...)
	combined = append(combined, data...)
	sum := sha256.Sum256(combined)
	out := make([]byte, len(sum))
	copy(out, sum[:])
	return out
}

func SHA224(data []byte) []byte {
	sum := sha256.Sum224(data)
	out := make([]byte, len(sum))
	copy(out, sum[:])
	return out
}

func MD5(data []byte) []byte {
	sum := md5.Sum(data)
	out := make([]byte, len(sum))
	copy(out, sum[:])
	return out
}

func SHA512(data []byte) []byte {
	sum := sha512.Sum512(data)
	out := make([]byte, len(sum))
	copy(out, sum[:])
	return out
}
