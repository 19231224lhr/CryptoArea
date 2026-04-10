package pre

import (
	"crypto/rand"
	"fmt"

	"github.com/19231224lhr/CryptoArea/crypto/signature/secp256k1"
	"github.com/19231224lhr/CryptoArea/crypto/symmetric"
)

const SchemeSecp256k1ECIESAESGCMV1 = "pre-secp256k1-ecies-aesgcm-v1"

const (
	DefaultDataKeySize = 32
	GCMNonceSize       = 12
)

type Payload struct {
	Scheme     string
	Nonce      []byte
	Ciphertext []byte
	AAD        []byte
}

type RecipientMessage struct {
	Scheme             string
	RecipientPublicKey []byte
	WrappedKey         []byte
}

type DelegationToken struct {
	Scheme             string
	ProxyPublicKey     []byte
	DelegateePublicKey []byte
	WrappedKeyForProxy []byte
	Metadata           []byte
}

type EncryptedMessage struct {
	Payload   *Payload
	Recipient *RecipientMessage
}

// ValidatePayload reports whether the payload is structurally well-formed.
func ValidatePayload(payload *Payload) error {
	return validatePayload(payload)
}

// ValidateRecipientMessage reports whether the wrapped-key message is
// structurally well-formed.
func ValidateRecipientMessage(message *RecipientMessage) error {
	return validateRecipientMessage(message)
}

// ValidateDelegationToken reports whether the delegation token is
// structurally well-formed.
func ValidateDelegationToken(token *DelegationToken) error {
	return validateDelegationToken(token)
}

// ValidateEncryptedMessage reports whether the full encrypted envelope is
// structurally well-formed.
func ValidateEncryptedMessage(message *EncryptedMessage) error {
	if message == nil {
		return fmt.Errorf("encrypted message must not be nil")
	}
	if err := validatePayload(message.Payload); err != nil {
		return err
	}
	if err := validateRecipientMessage(message.Recipient); err != nil {
		return err
	}
	return nil
}

func GenerateDataKey(size int) ([]byte, error) {
	if size <= 0 {
		return nil, fmt.Errorf("invalid data key size: %d", size)
	}
	out := make([]byte, size)
	if _, err := rand.Read(out); err != nil {
		return nil, err
	}
	return out, nil
}

func EncryptPayload(plaintext []byte, aad []byte, dataKey []byte) (*Payload, error) {
	if len(dataKey) == 0 {
		return nil, fmt.Errorf("data key must not be empty")
	}
	nonce := make([]byte, GCMNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext, err := symmetric.AESGCMEncrypt(dataKey, nonce, plaintext, aad)
	if err != nil {
		return nil, err
	}
	return &Payload{
		Scheme:     SchemeSecp256k1ECIESAESGCMV1,
		Nonce:      nonce,
		Ciphertext: ciphertext,
		AAD:        cloneBytes(aad),
	}, nil
}

func DecryptPayload(payload *Payload, dataKey []byte) ([]byte, error) {
	if err := validatePayload(payload); err != nil {
		return nil, err
	}
	if len(dataKey) == 0 {
		return nil, fmt.Errorf("data key must not be empty")
	}
	return symmetric.AESGCMDecrypt(dataKey, payload.Nonce, payload.Ciphertext, payload.AAD)
}

func WrapDataKeyForRecipient(recipientPublicKey []byte, dataKey []byte) (*RecipientMessage, error) {
	if len(dataKey) == 0 {
		return nil, fmt.Errorf("data key must not be empty")
	}
	wrappedKey, err := secp256k1.ECIESEncrypt(recipientPublicKey, dataKey)
	if err != nil {
		return nil, err
	}
	normalizedRecipientKey, err := secp256k1.NormalizePublicKey(recipientPublicKey, secp256k1.PublicKeyCompressed)
	if err != nil {
		return nil, err
	}
	return &RecipientMessage{
		Scheme:             SchemeSecp256k1ECIESAESGCMV1,
		RecipientPublicKey: normalizedRecipientKey,
		WrappedKey:         wrappedKey,
	}, nil
}

func UnwrapDataKeyForRecipient(recipientPrivateKey []byte, message *RecipientMessage) ([]byte, error) {
	if err := validateRecipientMessage(message); err != nil {
		return nil, err
	}
	return secp256k1.ECIESDecrypt(recipientPrivateKey, message.WrappedKey)
}

func EncryptForRecipient(plaintext []byte, aad []byte, recipientPublicKey []byte) (*EncryptedMessage, error) {
	dataKey, err := GenerateDataKey(DefaultDataKeySize)
	if err != nil {
		return nil, err
	}
	payload, err := EncryptPayload(plaintext, aad, dataKey)
	if err != nil {
		return nil, err
	}
	recipientMessage, err := WrapDataKeyForRecipient(recipientPublicKey, dataKey)
	if err != nil {
		return nil, err
	}
	return &EncryptedMessage{
		Payload:   payload,
		Recipient: recipientMessage,
	}, nil
}

func DecryptFromRecipient(message *EncryptedMessage, recipientPrivateKey []byte) ([]byte, error) {
	if message == nil {
		return nil, fmt.Errorf("encrypted message must not be nil")
	}
	dataKey, err := UnwrapDataKeyForRecipient(recipientPrivateKey, message.Recipient)
	if err != nil {
		return nil, err
	}
	return DecryptPayload(message.Payload, dataKey)
}

func CreateDelegationToken(proxyPublicKey []byte, delegateePublicKey []byte, dataKey []byte, metadata []byte) (*DelegationToken, error) {
	if len(dataKey) == 0 {
		return nil, fmt.Errorf("data key must not be empty")
	}
	wrappedKeyForProxy, err := secp256k1.ECIESEncrypt(proxyPublicKey, dataKey)
	if err != nil {
		return nil, err
	}
	normalizedProxyPublicKey, err := secp256k1.NormalizePublicKey(proxyPublicKey, secp256k1.PublicKeyCompressed)
	if err != nil {
		return nil, err
	}
	normalizedDelegateePublicKey, err := secp256k1.NormalizePublicKey(delegateePublicKey, secp256k1.PublicKeyCompressed)
	if err != nil {
		return nil, err
	}
	return &DelegationToken{
		Scheme:             SchemeSecp256k1ECIESAESGCMV1,
		ProxyPublicKey:     normalizedProxyPublicKey,
		DelegateePublicKey: normalizedDelegateePublicKey,
		WrappedKeyForProxy: wrappedKeyForProxy,
		Metadata:           cloneBytes(metadata),
	}, nil
}

func ReEncryptDataKey(token *DelegationToken, proxyPrivateKey []byte) (*RecipientMessage, error) {
	if err := validateDelegationToken(token); err != nil {
		return nil, err
	}
	derivedProxyPublicKey, err := secp256k1.DerivePublicKey(proxyPrivateKey, secp256k1.PublicKeyCompressed)
	if err != nil {
		return nil, err
	}
	if string(derivedProxyPublicKey) != string(token.ProxyPublicKey) {
		return nil, fmt.Errorf("proxy private key does not match delegation token")
	}
	dataKey, err := secp256k1.ECIESDecrypt(proxyPrivateKey, token.WrappedKeyForProxy)
	if err != nil {
		return nil, err
	}
	return WrapDataKeyForRecipient(token.DelegateePublicKey, dataKey)
}

func DecryptReEncryptedPayload(payload *Payload, recipientMessage *RecipientMessage, recipientPrivateKey []byte) ([]byte, error) {
	dataKey, err := UnwrapDataKeyForRecipient(recipientPrivateKey, recipientMessage)
	if err != nil {
		return nil, err
	}
	return DecryptPayload(payload, dataKey)
}

func validatePayload(payload *Payload) error {
	if payload == nil {
		return fmt.Errorf("payload must not be nil")
	}
	if payload.Scheme != SchemeSecp256k1ECIESAESGCMV1 {
		return fmt.Errorf("unsupported payload scheme: %s", payload.Scheme)
	}
	if len(payload.Nonce) != GCMNonceSize {
		return fmt.Errorf("invalid payload nonce length: got %d want %d", len(payload.Nonce), GCMNonceSize)
	}
	if len(payload.Ciphertext) == 0 {
		return fmt.Errorf("payload ciphertext must not be empty")
	}
	return nil
}

func validateRecipientMessage(message *RecipientMessage) error {
	if message == nil {
		return fmt.Errorf("recipient message must not be nil")
	}
	if message.Scheme != SchemeSecp256k1ECIESAESGCMV1 {
		return fmt.Errorf("unsupported recipient message scheme: %s", message.Scheme)
	}
	if len(message.RecipientPublicKey) == 0 {
		return fmt.Errorf("recipient public key must not be empty")
	}
	if len(message.WrappedKey) == 0 {
		return fmt.Errorf("wrapped key must not be empty")
	}
	return nil
}

func validateDelegationToken(token *DelegationToken) error {
	if token == nil {
		return fmt.Errorf("delegation token must not be nil")
	}
	if token.Scheme != SchemeSecp256k1ECIESAESGCMV1 {
		return fmt.Errorf("unsupported delegation token scheme: %s", token.Scheme)
	}
	if len(token.ProxyPublicKey) == 0 {
		return fmt.Errorf("proxy public key must not be empty")
	}
	if len(token.DelegateePublicKey) == 0 {
		return fmt.Errorf("delegatee public key must not be empty")
	}
	if len(token.WrappedKeyForProxy) == 0 {
		return fmt.Errorf("wrapped key for proxy must not be empty")
	}
	return nil
}

func cloneBytes(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	out := make([]byte, len(data))
	copy(out, data)
	return out
}
