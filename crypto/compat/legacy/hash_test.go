package legacy

import "testing"

func TestLegacyHashesReturnExpectedLengths(t *testing.T) {
	if got := len(SHA256Concat([]byte("k"), []byte("v"))); got != 32 {
		t.Fatalf("unexpected SHA256Concat length: %d", got)
	}
	if got := len(SHA224([]byte("abc"))); got != 28 {
		t.Fatalf("unexpected SHA224 length: %d", got)
	}
	if got := len(MD5([]byte("abc"))); got != 16 {
		t.Fatalf("unexpected MD5 length: %d", got)
	}
	if got := len(SHA512([]byte("abc"))); got != 64 {
		t.Fatalf("unexpected SHA512 length: %d", got)
	}
}
