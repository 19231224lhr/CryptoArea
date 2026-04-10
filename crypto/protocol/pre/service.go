package pre

import "fmt"

type Service interface {
	CodecName() string
	HashAlgorithm() string
	MarshalPayload(payload *Payload) ([]byte, error)
	UnmarshalPayload(data []byte) (*Payload, error)
	MarshalRecipientMessage(message *RecipientMessage) ([]byte, error)
	UnmarshalRecipientMessage(data []byte) (*RecipientMessage, error)
	MarshalDelegationToken(token *DelegationToken) ([]byte, error)
	UnmarshalDelegationToken(data []byte) (*DelegationToken, error)
	MarshalEncryptedMessage(message *EncryptedMessage) ([]byte, error)
	UnmarshalEncryptedMessage(data []byte) (*EncryptedMessage, error)
	PayloadHash(payload *Payload) ([]byte, error)
	RecipientMessageHash(message *RecipientMessage) ([]byte, error)
	DelegationTokenHash(token *DelegationToken) ([]byte, error)
	EncryptedMessageHash(message *EncryptedMessage) ([]byte, error)
}

type Option func(*service)

type service struct {
	hashAlgorithm string
}

func NewService(options ...Option) (Service, error) {
	svc := &service{hashAlgorithm: HashAlgorithmKeccak256}
	for _, option := range options {
		option(svc)
	}
	if _, err := HashBytes(svc.hashAlgorithm, nil); err != nil {
		return nil, err
	}
	return svc, nil
}

func MustNewService(options ...Option) Service {
	svc, err := NewService(options...)
	if err != nil {
		panic(err)
	}
	return svc
}

func WithHashAlgorithm(algorithm string) Option {
	return func(svc *service) {
		svc.hashAlgorithm = algorithm
	}
}

func (s *service) CodecName() string {
	return SchemeSecp256k1ECIESAESGCMV1
}

func (s *service) HashAlgorithm() string {
	return s.hashAlgorithm
}

func (s *service) MarshalPayload(payload *Payload) ([]byte, error) {
	return MarshalPayload(payload)
}

func (s *service) UnmarshalPayload(data []byte) (*Payload, error) {
	return UnmarshalPayload(data)
}

func (s *service) MarshalRecipientMessage(message *RecipientMessage) ([]byte, error) {
	return MarshalRecipientMessage(message)
}

func (s *service) UnmarshalRecipientMessage(data []byte) (*RecipientMessage, error) {
	return UnmarshalRecipientMessage(data)
}

func (s *service) MarshalDelegationToken(token *DelegationToken) ([]byte, error) {
	return MarshalDelegationToken(token)
}

func (s *service) UnmarshalDelegationToken(data []byte) (*DelegationToken, error) {
	return UnmarshalDelegationToken(data)
}

func (s *service) MarshalEncryptedMessage(message *EncryptedMessage) ([]byte, error) {
	return MarshalEncryptedMessage(message)
}

func (s *service) UnmarshalEncryptedMessage(data []byte) (*EncryptedMessage, error) {
	return UnmarshalEncryptedMessage(data)
}

func (s *service) PayloadHash(payload *Payload) ([]byte, error) {
	encoded, err := MarshalPayload(payload)
	if err != nil {
		return nil, err
	}
	return HashBytes(s.hashAlgorithm, encoded)
}

func (s *service) RecipientMessageHash(message *RecipientMessage) ([]byte, error) {
	encoded, err := MarshalRecipientMessage(message)
	if err != nil {
		return nil, err
	}
	return HashBytes(s.hashAlgorithm, encoded)
}

func (s *service) DelegationTokenHash(token *DelegationToken) ([]byte, error) {
	encoded, err := MarshalDelegationToken(token)
	if err != nil {
		return nil, err
	}
	return HashBytes(s.hashAlgorithm, encoded)
}

func (s *service) EncryptedMessageHash(message *EncryptedMessage) ([]byte, error) {
	encoded, err := MarshalEncryptedMessage(message)
	if err != nil {
		return nil, err
	}
	return HashBytes(s.hashAlgorithm, encoded)
}

func ValidateService(svc Service) error {
	if svc == nil {
		return fmt.Errorf("service must not be nil")
	}
	if svc.CodecName() == "" {
		return fmt.Errorf("service codec name must not be empty")
	}
	if _, err := HashBytes(svc.HashAlgorithm(), nil); err != nil {
		return err
	}
	return nil
}
