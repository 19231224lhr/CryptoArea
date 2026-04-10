package pre

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type goldenVectors struct {
	PayloadJSON               string `json:"payload_json"`
	RecipientJSON             string `json:"recipient_json"`
	DelegationTokenJSON       string `json:"delegation_token_json"`
	EncryptedMessageJSON      string `json:"encrypted_message_json"`
	PayloadKeccak256          string `json:"payload_keccak256"`
	RecipientKeccak256        string `json:"recipient_keccak256"`
	DelegationTokenKeccak256  string `json:"delegation_token_keccak256"`
	EncryptedMessageKeccak256 string `json:"encrypted_message_keccak256"`
	PayloadSHA256             string `json:"payload_sha256"`
	RecipientSHA256           string `json:"recipient_sha256"`
	DelegationTokenSHA256     string `json:"delegation_token_sha256"`
	EncryptedMessageSHA256    string `json:"encrypted_message_sha256"`
}

func TestGoldenVectorsMatchCodecAndHashes(t *testing.T) {
	vectors := loadGoldenVectors(t)
	payload, recipient, token, message := buildGoldenObjects()

	payloadJSON, err := MarshalPayload(payload)
	if err != nil {
		t.Fatalf("MarshalPayload failed: %v", err)
	}
	if string(payloadJSON) != vectors.PayloadJSON {
		t.Fatalf("unexpected payload json: got %s want %s", string(payloadJSON), vectors.PayloadJSON)
	}

	recipientJSON, err := MarshalRecipientMessage(recipient)
	if err != nil {
		t.Fatalf("MarshalRecipientMessage failed: %v", err)
	}
	if string(recipientJSON) != vectors.RecipientJSON {
		t.Fatalf("unexpected recipient json: got %s want %s", string(recipientJSON), vectors.RecipientJSON)
	}

	tokenJSON, err := MarshalDelegationToken(token)
	if err != nil {
		t.Fatalf("MarshalDelegationToken failed: %v", err)
	}
	if string(tokenJSON) != vectors.DelegationTokenJSON {
		t.Fatalf("unexpected delegation token json: got %s want %s", string(tokenJSON), vectors.DelegationTokenJSON)
	}

	messageJSON, err := MarshalEncryptedMessage(message)
	if err != nil {
		t.Fatalf("MarshalEncryptedMessage failed: %v", err)
	}
	if string(messageJSON) != vectors.EncryptedMessageJSON {
		t.Fatalf("unexpected encrypted message json: got %s want %s", string(messageJSON), vectors.EncryptedMessageJSON)
	}

	keccakService := MustNewService()
	payloadKeccak, err := keccakService.PayloadHash(payload)
	assertHash(t, payloadKeccak, err, vectors.PayloadKeccak256, "payload keccak256")
	recipientKeccak, err := keccakService.RecipientMessageHash(recipient)
	assertHash(t, recipientKeccak, err, vectors.RecipientKeccak256, "recipient keccak256")
	tokenKeccak, err := keccakService.DelegationTokenHash(token)
	assertHash(t, tokenKeccak, err, vectors.DelegationTokenKeccak256, "delegation token keccak256")
	messageKeccak, err := keccakService.EncryptedMessageHash(message)
	assertHash(t, messageKeccak, err, vectors.EncryptedMessageKeccak256, "encrypted message keccak256")

	shaService := MustNewService(WithHashAlgorithm(HashAlgorithmSHA256))
	payloadSHA, err := shaService.PayloadHash(payload)
	assertHash(t, payloadSHA, err, vectors.PayloadSHA256, "payload sha256")
	recipientSHA, err := shaService.RecipientMessageHash(recipient)
	assertHash(t, recipientSHA, err, vectors.RecipientSHA256, "recipient sha256")
	tokenSHA, err := shaService.DelegationTokenHash(token)
	assertHash(t, tokenSHA, err, vectors.DelegationTokenSHA256, "delegation token sha256")
	messageSHA, err := shaService.EncryptedMessageHash(message)
	assertHash(t, messageSHA, err, vectors.EncryptedMessageSHA256, "encrypted message sha256")

	decodedPayload, err := UnmarshalPayload(payloadJSON)
	if err != nil {
		t.Fatalf("UnmarshalPayload failed: %v", err)
	}
	if !bytes.Equal(decodedPayload.Ciphertext, payload.Ciphertext) {
		t.Fatal("payload round-trip mismatch")
	}
	decodedRecipient, err := UnmarshalRecipientMessage(recipientJSON)
	if err != nil {
		t.Fatalf("UnmarshalRecipientMessage failed: %v", err)
	}
	if !bytes.Equal(decodedRecipient.WrappedKey, recipient.WrappedKey) {
		t.Fatal("recipient round-trip mismatch")
	}
	decodedToken, err := UnmarshalDelegationToken(tokenJSON)
	if err != nil {
		t.Fatalf("UnmarshalDelegationToken failed: %v", err)
	}
	if !bytes.Equal(decodedToken.WrappedKeyForProxy, token.WrappedKeyForProxy) {
		t.Fatal("delegation token round-trip mismatch")
	}
	decodedMessage, err := UnmarshalEncryptedMessage(messageJSON)
	if err != nil {
		t.Fatalf("UnmarshalEncryptedMessage failed: %v", err)
	}
	if !bytes.Equal(decodedMessage.Payload.Ciphertext, message.Payload.Ciphertext) {
		t.Fatal("encrypted message round-trip mismatch")
	}
}

func TestValidateAndServiceHelpers(t *testing.T) {
	payload, recipient, token, message := buildGoldenObjects()
	svc := MustNewService(WithHashAlgorithm(HashAlgorithmSHA256))
	if err := ValidateService(svc); err != nil {
		t.Fatalf("ValidateService failed: %v", err)
	}
	if err := ValidatePayload(payload); err != nil {
		t.Fatalf("ValidatePayload failed: %v", err)
	}
	if err := ValidateRecipientMessage(recipient); err != nil {
		t.Fatalf("ValidateRecipientMessage failed: %v", err)
	}
	if err := ValidateDelegationToken(token); err != nil {
		t.Fatalf("ValidateDelegationToken failed: %v", err)
	}
	if err := ValidateEncryptedMessage(message); err != nil {
		t.Fatalf("ValidateEncryptedMessage failed: %v", err)
	}
	if _, err := NewService(WithHashAlgorithm("unknown")); err == nil {
		t.Fatal("expected NewService to reject unknown hash algorithm")
	}
}

func loadGoldenVectors(t *testing.T) *goldenVectors {
	t.Helper()
	path := filepath.Join("testdata", "reference_v1_golden.json")
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	var vectors goldenVectors
	if err := json.Unmarshal(payload, &vectors); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	return &vectors
}

func buildGoldenObjects() (*Payload, *RecipientMessage, *DelegationToken, *EncryptedMessage) {
	payload := &Payload{
		Scheme:     SchemeSecp256k1ECIESAESGCMV1,
		Nonce:      []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b},
		Ciphertext: []byte{0xaa, 0xbb, 0xcc, 0xdd},
		AAD:        []byte("aad"),
	}
	recipient := &RecipientMessage{
		Scheme:             SchemeSecp256k1ECIESAESGCMV1,
		RecipientPublicKey: []byte{0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98},
		WrappedKey:         []byte{0x10, 0x20, 0x30, 0x40},
	}
	token := &DelegationToken{
		Scheme:             SchemeSecp256k1ECIESAESGCMV1,
		ProxyPublicKey:     []byte{0x02, 0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d, 0x30, 0x45, 0x40, 0x6e, 0x95, 0xc0, 0x7c, 0xd8, 0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7, 0xab, 0xac, 0x09, 0xb9, 0x5c, 0x70, 0x9e, 0xe5},
		DelegateePublicKey: recipient.RecipientPublicKey,
		WrappedKeyForProxy: []byte{0x50, 0x60, 0x70, 0x80},
		Metadata:           []byte("meta"),
	}
	message := &EncryptedMessage{
		Payload:   payload,
		Recipient: recipient,
	}
	return payload, recipient, token, message
}

func assertHash(t *testing.T, got []byte, err error, want string, label string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s failed: %v", label, err)
	}
	if "0x"+hexEncode(got) != want {
		t.Fatalf("unexpected %s: got 0x%s want %s", label, hexEncode(got), want)
	}
}

func hexEncode(raw []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(raw)*2)
	for i, b := range raw {
		out[i*2] = hexdigits[b>>4]
		out[i*2+1] = hexdigits[b&0x0f]
	}
	return string(out)
}
