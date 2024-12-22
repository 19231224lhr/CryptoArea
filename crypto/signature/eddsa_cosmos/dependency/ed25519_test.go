package ed25519

import (
	crypto "blockchain-crypto/signature/eddsa_cosmos/dependency/cometcrypto"
	cryptotypes "blockchain-crypto/signature/eddsa_cosmos/dependency/types"
	stded25519 "crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignAndValidateEd25519(t *testing.T) {
	privKey := GenPrivKey()
	pubKey := privKey.PubKey()

	msg := crypto.CRandBytes(1000)
	sig, err := privKey.Sign(msg)
	require.Nil(t, err)

	// Test the signature
	assert.True(t, pubKey.VerifySignature(msg, sig))

	// ----
	// Test cross packages verification
	stdPrivKey := privKey.Key
	stdPubKey := stdPrivKey.Public().(stded25519.PublicKey)

	assert.Equal(t, stdPubKey, pubKey.(*PubKey).Key)
	assert.Equal(t, stdPrivKey, privKey.Key)
	assert.True(t, stded25519.Verify(stdPubKey, msg, sig))
	sig2 := stded25519.Sign(stdPrivKey, msg)
	assert.True(t, pubKey.VerifySignature(msg, sig2))

	// ----
	// Mutate the signature, just one bit.
	// TODO: Replace this with a much better fuzzer, tendermint/ed25519/issues/10
	sig[7] ^= byte(0x01)
	assert.False(t, pubKey.VerifySignature(msg, sig))
}
func TestPubKeyEquals(t *testing.T) {
	ed25519PubKey := GenPrivKey().PubKey().(*PubKey)

	testCases := []struct {
		msg      string
		pubKey   cryptotypes.PubKey
		other    cryptotypes.PubKey
		expectEq bool
	}{
		{
			"different bytes",
			ed25519PubKey,
			GenPrivKey().PubKey(),
			false,
		},
		{
			"equals",
			ed25519PubKey,
			&PubKey{
				Key: ed25519PubKey.Key,
			},
			true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.msg, func(t *testing.T) {
			eq := tc.pubKey.Equals(tc.other)
			require.Equal(t, eq, tc.expectEq)
		})
	}
}

func TestAddressEd25519(t *testing.T) {
	pk := PubKey{[]byte{125, 80, 29, 208, 159, 53, 119, 198, 73, 53, 187, 33, 199, 144, 62, 255, 1, 235, 117, 96, 128, 211, 17, 45, 34, 64, 189, 165, 33, 182, 54, 206}}
	addr := pk.Address()
	require.Len(t, addr, 20, "Address must be 20 bytes long")
}

func TestPrivKeyEquals(t *testing.T) {
	ed25519PrivKey := GenPrivKey()

	testCases := []struct {
		msg      string
		privKey  cryptotypes.PrivKey
		other    cryptotypes.PrivKey
		expectEq bool
	}{
		{
			"different bytes",
			ed25519PrivKey,
			GenPrivKey(),
			false,
		},
		{
			"equals",
			ed25519PrivKey,
			&PrivKey{
				Key: ed25519PrivKey.Key,
			},
			true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.msg, func(t *testing.T) {
			eq := tc.privKey.Equals(tc.other)
			require.Equal(t, eq, tc.expectEq)
		})
	}
}
