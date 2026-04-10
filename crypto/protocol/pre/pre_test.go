package pre

import (
	"bytes"
	"testing"

	"github.com/19231224lhr/CryptoArea/crypto/signature/secp256k1"
)

func TestEncryptForRecipientRoundTrip(t *testing.T) {
	recipientPrivateKey, recipientPublicKey, err := secp256k1.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	message, err := EncryptForRecipient([]byte("hello trusted pre"), []byte("aad"), recipientPublicKey)
	if err != nil {
		t.Fatalf("EncryptForRecipient failed: %v", err)
	}
	plaintext, err := DecryptFromRecipient(message, recipientPrivateKey)
	if err != nil {
		t.Fatalf("DecryptFromRecipient failed: %v", err)
	}
	if string(plaintext) != "hello trusted pre" {
		t.Fatalf("unexpected plaintext: %s", string(plaintext))
	}
}

func TestWrapAndUnwrapDataKey(t *testing.T) {
	recipientPrivateKey, recipientPublicKey, err := secp256k1.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	dataKey, err := GenerateDataKey(DefaultDataKeySize)
	if err != nil {
		t.Fatalf("GenerateDataKey failed: %v", err)
	}

	message, err := WrapDataKeyForRecipient(recipientPublicKey, dataKey)
	if err != nil {
		t.Fatalf("WrapDataKeyForRecipient failed: %v", err)
	}
	roundTripKey, err := UnwrapDataKeyForRecipient(recipientPrivateKey, message)
	if err != nil {
		t.Fatalf("UnwrapDataKeyForRecipient failed: %v", err)
	}
	if !bytes.Equal(roundTripKey, dataKey) {
		t.Fatal("wrapped data key round-trip mismatch")
	}
}

func TestTrustedProxyReEncryptionFlow(t *testing.T) {
	ownerDataKey, err := GenerateDataKey(DefaultDataKeySize)
	if err != nil {
		t.Fatalf("GenerateDataKey failed: %v", err)
	}
	payload, err := EncryptPayload([]byte("payload through proxy"), []byte("aad"), ownerDataKey)
	if err != nil {
		t.Fatalf("EncryptPayload failed: %v", err)
	}

	proxyPrivateKey, proxyPublicKey, err := secp256k1.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(proxy) failed: %v", err)
	}
	delegateePrivateKey, delegateePublicKey, err := secp256k1.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(delegatee) failed: %v", err)
	}

	token, err := CreateDelegationToken(proxyPublicKey, delegateePublicKey, ownerDataKey, []byte("metadata"))
	if err != nil {
		t.Fatalf("CreateDelegationToken failed: %v", err)
	}
	recipientMessage, err := ReEncryptDataKey(token, proxyPrivateKey)
	if err != nil {
		t.Fatalf("ReEncryptDataKey failed: %v", err)
	}
	plaintext, err := DecryptReEncryptedPayload(payload, recipientMessage, delegateePrivateKey)
	if err != nil {
		t.Fatalf("DecryptReEncryptedPayload failed: %v", err)
	}
	if string(plaintext) != "payload through proxy" {
		t.Fatalf("unexpected delegatee plaintext: %s", string(plaintext))
	}
}

func TestProxyPrivateKeyMismatchFails(t *testing.T) {
	_, proxyPublicKey, err := secp256k1.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(proxy) failed: %v", err)
	}
	otherProxyPrivateKey, _, err := secp256k1.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(other proxy) failed: %v", err)
	}
	delegateePrivateKey, delegateePublicKey, err := secp256k1.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(delegatee) failed: %v", err)
	}
	_ = delegateePrivateKey
	dataKey, err := GenerateDataKey(DefaultDataKeySize)
	if err != nil {
		t.Fatalf("GenerateDataKey failed: %v", err)
	}
	token, err := CreateDelegationToken(proxyPublicKey, delegateePublicKey, dataKey, nil)
	if err != nil {
		t.Fatalf("CreateDelegationToken failed: %v", err)
	}
	if _, err := ReEncryptDataKey(token, otherProxyPrivateKey); err == nil {
		t.Fatal("expected ReEncryptDataKey to fail with a mismatched proxy private key")
	}
}

func TestInvalidInputsFail(t *testing.T) {
	if _, err := GenerateDataKey(0); err == nil {
		t.Fatal("expected GenerateDataKey to fail")
	}
	if _, err := EncryptPayload([]byte("m"), nil, nil); err == nil {
		t.Fatal("expected EncryptPayload to fail")
	}
	if _, err := DecryptPayload(nil, []byte("key")); err == nil {
		t.Fatal("expected DecryptPayload to fail")
	}
	if _, err := UnwrapDataKeyForRecipient(nil, nil); err == nil {
		t.Fatal("expected UnwrapDataKeyForRecipient to fail")
	}
}
