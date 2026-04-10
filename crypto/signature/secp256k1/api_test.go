package secp256k1

import "testing"

func TestGenerateKeyPairAndDerivePublicKey(t *testing.T) {
	privateKey, publicKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if len(privateKey) != PrivateKeyBytesLen {
		t.Fatalf("unexpected private key length: got %d want %d", len(privateKey), PrivateKeyBytesLen)
	}
	if len(publicKey) != PublicKeyCompressedBytesLen {
		t.Fatalf("unexpected public key length: got %d want %d", len(publicKey), PublicKeyCompressedBytesLen)
	}

	uncompressed, err := DerivePublicKey(privateKey, PublicKeyUncompressed)
	if err != nil {
		t.Fatalf("DerivePublicKey failed: %v", err)
	}
	if len(uncompressed) != PublicKeyUncompressedBytesLen {
		t.Fatalf("unexpected uncompressed public key length: got %d want %d", len(uncompressed), PublicKeyUncompressedBytesLen)
	}

	normalizedCompressed, err := NormalizePublicKey(uncompressed, PublicKeyCompressed)
	if err != nil {
		t.Fatalf("NormalizePublicKey failed: %v", err)
	}
	if string(normalizedCompressed) != string(publicKey) {
		t.Fatal("NormalizePublicKey did not preserve the original compressed key")
	}
}

func TestSignDERAndVerifyDER(t *testing.T) {
	privateKey, publicKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	digest := []byte("digest-for-secp256k1")
	signatureDER, err := SignDER(privateKey, digest)
	if err != nil {
		t.Fatalf("SignDER failed: %v", err)
	}
	ok, err := VerifyDER(publicKey, digest, signatureDER)
	if err != nil {
		t.Fatalf("VerifyDER failed: %v", err)
	}
	if !ok {
		t.Fatal("VerifyDER returned false")
	}
}

func TestSignCompactAndRecoverPublicKey(t *testing.T) {
	privateKey, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	expectedUncompressed, err := DerivePublicKey(privateKey, PublicKeyUncompressed)
	if err != nil {
		t.Fatalf("DerivePublicKey failed: %v", err)
	}

	digest := []byte("recoverable-digest")
	signatureCompact, err := SignCompact(privateKey, digest, false)
	if err != nil {
		t.Fatalf("SignCompact failed: %v", err)
	}

	recoveredPublicKey, err := RecoverPublicKey(digest, signatureCompact, PublicKeyUncompressed)
	if err != nil {
		t.Fatalf("RecoverPublicKey failed: %v", err)
	}
	if string(recoveredPublicKey) != string(expectedUncompressed) {
		t.Fatal("recovered public key does not match expected uncompressed public key")
	}
}

func TestSharedSecretAndECIESHelpers(t *testing.T) {
	privateKeyA, publicKeyA, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair A failed: %v", err)
	}
	privateKeyB, publicKeyB, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair B failed: %v", err)
	}

	sharedSecretAB, err := ComputeSharedSecret(privateKeyA, publicKeyB)
	if err != nil {
		t.Fatalf("ComputeSharedSecret AB failed: %v", err)
	}
	sharedSecretBA, err := ComputeSharedSecret(privateKeyB, publicKeyA)
	if err != nil {
		t.Fatalf("ComputeSharedSecret BA failed: %v", err)
	}
	if string(sharedSecretAB) != string(sharedSecretBA) {
		t.Fatal("shared secrets mismatch")
	}

	ciphertext, err := ECIESEncrypt(publicKeyA, []byte("hello ecies"))
	if err != nil {
		t.Fatalf("ECIESEncrypt failed: %v", err)
	}
	plaintext, err := ECIESDecrypt(privateKeyA, ciphertext)
	if err != nil {
		t.Fatalf("ECIESDecrypt failed: %v", err)
	}
	if string(plaintext) != "hello ecies" {
		t.Fatalf("unexpected plaintext: %s", string(plaintext))
	}
}

func TestInvalidInputsReturnErrors(t *testing.T) {
	if _, err := DerivePublicKey([]byte{1}, PublicKeyCompressed); err == nil {
		t.Fatal("expected DerivePublicKey to fail")
	}
	if _, err := SignDER(make([]byte, PrivateKeyBytesLen), nil); err == nil {
		t.Fatal("expected SignDER to fail")
	}
	if _, err := RecoverPublicKey(nil, make([]byte, CompactSignatureBytesLen), PublicKeyCompressed); err == nil {
		t.Fatal("expected RecoverPublicKey to fail")
	}
}
