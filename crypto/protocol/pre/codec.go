package pre

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/19231224lhr/CryptoArea/crypto/encoding/canonical"
)

type WirePayload struct {
	Scheme     string `json:"scheme"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
	AAD        string `json:"aad,omitempty"`
}

type WireRecipientMessage struct {
	Scheme             string `json:"scheme"`
	RecipientPublicKey string `json:"recipient_public_key"`
	WrappedKey         string `json:"wrapped_key"`
}

type WireDelegationToken struct {
	Scheme             string `json:"scheme"`
	ProxyPublicKey     string `json:"proxy_public_key"`
	DelegateePublicKey string `json:"delegatee_public_key"`
	WrappedKeyForProxy string `json:"wrapped_key_for_proxy"`
	Metadata           string `json:"metadata,omitempty"`
}

type WireEncryptedMessage struct {
	Payload   *WirePayload          `json:"payload"`
	Recipient *WireRecipientMessage `json:"recipient"`
}

func MarshalPayload(payload *Payload) ([]byte, error) {
	wire, err := ToWirePayload(payload)
	if err != nil {
		return nil, err
	}
	return canonical.Marshal(wire)
}

func UnmarshalPayload(data []byte) (*Payload, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("payload bytes must not be empty")
	}
	var wire WirePayload
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, err
	}
	return FromWirePayload(&wire)
}

func MarshalRecipientMessage(message *RecipientMessage) ([]byte, error) {
	wire, err := ToWireRecipientMessage(message)
	if err != nil {
		return nil, err
	}
	return canonical.Marshal(wire)
}

func UnmarshalRecipientMessage(data []byte) (*RecipientMessage, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("recipient message bytes must not be empty")
	}
	var wire WireRecipientMessage
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, err
	}
	return FromWireRecipientMessage(&wire)
}

func MarshalDelegationToken(token *DelegationToken) ([]byte, error) {
	wire, err := ToWireDelegationToken(token)
	if err != nil {
		return nil, err
	}
	return canonical.Marshal(wire)
}

func UnmarshalDelegationToken(data []byte) (*DelegationToken, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("delegation token bytes must not be empty")
	}
	var wire WireDelegationToken
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, err
	}
	return FromWireDelegationToken(&wire)
}

func MarshalEncryptedMessage(message *EncryptedMessage) ([]byte, error) {
	wire, err := ToWireEncryptedMessage(message)
	if err != nil {
		return nil, err
	}
	return canonical.Marshal(wire)
}

func UnmarshalEncryptedMessage(data []byte) (*EncryptedMessage, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("encrypted message bytes must not be empty")
	}
	var wire WireEncryptedMessage
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, err
	}
	return FromWireEncryptedMessage(&wire)
}

func ToWirePayload(payload *Payload) (*WirePayload, error) {
	if err := ValidatePayload(payload); err != nil {
		return nil, err
	}
	return &WirePayload{
		Scheme:     payload.Scheme,
		Nonce:      encodeHex(payload.Nonce),
		Ciphertext: encodeHex(payload.Ciphertext),
		AAD:        encodeOptionalHex(payload.AAD),
	}, nil
}

func FromWirePayload(wire *WirePayload) (*Payload, error) {
	if wire == nil {
		return nil, fmt.Errorf("wire payload must not be nil")
	}
	nonce, err := decodeHex(wire.Nonce)
	if err != nil {
		return nil, err
	}
	ciphertext, err := decodeHex(wire.Ciphertext)
	if err != nil {
		return nil, err
	}
	aad, err := decodeOptionalHex(wire.AAD)
	if err != nil {
		return nil, err
	}
	payload := &Payload{
		Scheme:     wire.Scheme,
		Nonce:      nonce,
		Ciphertext: ciphertext,
		AAD:        aad,
	}
	if err := ValidatePayload(payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func ToWireRecipientMessage(message *RecipientMessage) (*WireRecipientMessage, error) {
	if err := ValidateRecipientMessage(message); err != nil {
		return nil, err
	}
	return &WireRecipientMessage{
		Scheme:             message.Scheme,
		RecipientPublicKey: encodeHex(message.RecipientPublicKey),
		WrappedKey:         encodeHex(message.WrappedKey),
	}, nil
}

func FromWireRecipientMessage(wire *WireRecipientMessage) (*RecipientMessage, error) {
	if wire == nil {
		return nil, fmt.Errorf("wire recipient message must not be nil")
	}
	recipientPublicKey, err := decodeHex(wire.RecipientPublicKey)
	if err != nil {
		return nil, err
	}
	wrappedKey, err := decodeHex(wire.WrappedKey)
	if err != nil {
		return nil, err
	}
	message := &RecipientMessage{
		Scheme:             wire.Scheme,
		RecipientPublicKey: recipientPublicKey,
		WrappedKey:         wrappedKey,
	}
	if err := ValidateRecipientMessage(message); err != nil {
		return nil, err
	}
	return message, nil
}

func ToWireDelegationToken(token *DelegationToken) (*WireDelegationToken, error) {
	if err := ValidateDelegationToken(token); err != nil {
		return nil, err
	}
	return &WireDelegationToken{
		Scheme:             token.Scheme,
		ProxyPublicKey:     encodeHex(token.ProxyPublicKey),
		DelegateePublicKey: encodeHex(token.DelegateePublicKey),
		WrappedKeyForProxy: encodeHex(token.WrappedKeyForProxy),
		Metadata:           encodeOptionalHex(token.Metadata),
	}, nil
}

func FromWireDelegationToken(wire *WireDelegationToken) (*DelegationToken, error) {
	if wire == nil {
		return nil, fmt.Errorf("wire delegation token must not be nil")
	}
	proxyPublicKey, err := decodeHex(wire.ProxyPublicKey)
	if err != nil {
		return nil, err
	}
	delegateePublicKey, err := decodeHex(wire.DelegateePublicKey)
	if err != nil {
		return nil, err
	}
	wrappedKeyForProxy, err := decodeHex(wire.WrappedKeyForProxy)
	if err != nil {
		return nil, err
	}
	metadata, err := decodeOptionalHex(wire.Metadata)
	if err != nil {
		return nil, err
	}
	token := &DelegationToken{
		Scheme:             wire.Scheme,
		ProxyPublicKey:     proxyPublicKey,
		DelegateePublicKey: delegateePublicKey,
		WrappedKeyForProxy: wrappedKeyForProxy,
		Metadata:           metadata,
	}
	if err := ValidateDelegationToken(token); err != nil {
		return nil, err
	}
	return token, nil
}

func ToWireEncryptedMessage(message *EncryptedMessage) (*WireEncryptedMessage, error) {
	if err := ValidateEncryptedMessage(message); err != nil {
		return nil, err
	}
	payload, err := ToWirePayload(message.Payload)
	if err != nil {
		return nil, err
	}
	recipient, err := ToWireRecipientMessage(message.Recipient)
	if err != nil {
		return nil, err
	}
	return &WireEncryptedMessage{
		Payload:   payload,
		Recipient: recipient,
	}, nil
}

func FromWireEncryptedMessage(wire *WireEncryptedMessage) (*EncryptedMessage, error) {
	if wire == nil {
		return nil, fmt.Errorf("wire encrypted message must not be nil")
	}
	payload, err := FromWirePayload(wire.Payload)
	if err != nil {
		return nil, err
	}
	recipient, err := FromWireRecipientMessage(wire.Recipient)
	if err != nil {
		return nil, err
	}
	message := &EncryptedMessage{
		Payload:   payload,
		Recipient: recipient,
	}
	if err := ValidateEncryptedMessage(message); err != nil {
		return nil, err
	}
	return message, nil
}

func encodeHex(data []byte) string {
	return "0x" + hex.EncodeToString(data)
}

func encodeOptionalHex(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	return encodeHex(data)
}

func decodeHex(value string) ([]byte, error) {
	trimmed := strings.TrimSpace(strings.TrimPrefix(value, "0x"))
	if trimmed == "" {
		return nil, fmt.Errorf("hex value must not be empty")
	}
	return hex.DecodeString(trimmed)
}

func decodeOptionalHex(value string) ([]byte, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	return decodeHex(value)
}
