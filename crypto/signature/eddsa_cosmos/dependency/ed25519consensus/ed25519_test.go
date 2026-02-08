package ed25519consensus_test

import (
	"blockchain-crypto/signature/eddsa_cosmos/dependency/ed25519consensus"
	"crypto/ed25519"
	"testing"
)

func BenchmarkVerification(b *testing.B) {
	b.ReportAllocs()
	pub, priv, _ := ed25519.GenerateKey(nil)
	hash := []byte("Single key verification")
	signature := ed25519.Sign(priv, hash)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ed25519consensus.Verify(pub, hash, signature)
	}
}
