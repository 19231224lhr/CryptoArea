package evm

import (
	"bytes"
	"testing"

	"github.com/19231224lhr/CryptoArea/crypto/signature/secp256k1"
)

func TestPublicKeyToAddressAcceptsCompressedAndUncompressed(t *testing.T) {
	privateKey, compressedPublicKey, err := secp256k1.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	uncompressedPublicKey, err := secp256k1.DerivePublicKey(privateKey, secp256k1.PublicKeyUncompressed)
	if err != nil {
		t.Fatalf("DerivePublicKey failed: %v", err)
	}

	addressFromCompressed, err := PublicKeyToAddress(compressedPublicKey)
	if err != nil {
		t.Fatalf("PublicKeyToAddress(compressed) failed: %v", err)
	}
	addressFromUncompressed, err := PublicKeyToAddress(uncompressedPublicKey)
	if err != nil {
		t.Fatalf("PublicKeyToAddress(uncompressed) failed: %v", err)
	}
	if addressFromCompressed != addressFromUncompressed {
		t.Fatal("expected compressed and uncompressed public keys to map to the same address")
	}
}

func TestRecoverAndVerifyPersonalSignAddress(t *testing.T) {
	privateKey, publicKey, err := secp256k1.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	expectedAddress, err := PublicKeyToAddress(publicKey)
	if err != nil {
		t.Fatalf("PublicKeyToAddress failed: %v", err)
	}

	message := []byte("hello from cryptoarea evm")
	signatureCompact, err := secp256k1.SignCompact(privateKey, PersonalSignHash(message), false)
	if err != nil {
		t.Fatalf("SignCompact failed: %v", err)
	}
	signature65, err := CompactSignatureToSignature65(signatureCompact)
	if err != nil {
		t.Fatalf("CompactSignatureToSignature65 failed: %v", err)
	}

	recoveredAddress, err := RecoverAddressFromPersonalSign(message, signature65)
	if err != nil {
		t.Fatalf("RecoverAddressFromPersonalSign failed: %v", err)
	}
	if recoveredAddress != expectedAddress {
		t.Fatalf("unexpected recovered address: got %s want %s", recoveredAddress, expectedAddress)
	}

	ok, err := VerifyPersonalSignAddress(message, signature65, expectedAddress)
	if err != nil {
		t.Fatalf("VerifyPersonalSignAddress failed: %v", err)
	}
	if !ok {
		t.Fatal("VerifyPersonalSignAddress returned false")
	}

	tamperedMessage := []byte("tampered message")
	ok, err = VerifyPersonalSignAddress(tamperedMessage, signature65, expectedAddress)
	if err != nil {
		t.Fatalf("VerifyPersonalSignAddress(tampered) failed: %v", err)
	}
	if ok {
		t.Fatal("expected tampered message verification to fail")
	}
}

func TestSignatureConversionRoundTrip(t *testing.T) {
	signatureCompact := make([]byte, secp256k1.CompactSignatureBytesLen)
	signatureCompact[0] = 28
	for i := 1; i < len(signatureCompact); i++ {
		signatureCompact[i] = byte(i)
	}

	signature65, err := CompactSignatureToSignature65(signatureCompact)
	if err != nil {
		t.Fatalf("CompactSignatureToSignature65 failed: %v", err)
	}
	roundTripCompact, err := Signature65ToCompact(signature65)
	if err != nil {
		t.Fatalf("Signature65ToCompact failed: %v", err)
	}
	if !bytes.Equal(signatureCompact, roundTripCompact) {
		t.Fatal("signature conversion round-trip mismatch")
	}
}

func TestBytes32HexValidatesLength(t *testing.T) {
	bytes32Hex, err := Bytes32Hex([]byte{0x01, 0x02, 0x03})
	if err != nil {
		t.Fatalf("Bytes32Hex failed: %v", err)
	}
	if len(bytes32Hex) != 66 {
		t.Fatalf("unexpected bytes32 hex length: got %d want 66", len(bytes32Hex))
	}
	if _, err := Bytes32Hex(make([]byte, 33)); err == nil {
		t.Fatal("expected Bytes32Hex to fail for oversized input")
	}
}
