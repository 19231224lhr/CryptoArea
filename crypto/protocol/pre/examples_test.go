package pre_test

import (
	"fmt"

	"github.com/19231224lhr/CryptoArea/crypto/protocol/pre"
)

func Example() {
	payload := &pre.Payload{
		Scheme:     pre.SchemeSecp256k1ECIESAESGCMV1,
		Nonce:      []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b},
		Ciphertext: []byte{0xaa, 0xbb, 0xcc, 0xdd},
		AAD:        []byte("aad"),
	}

	service := pre.MustNewService()
	encoded, err := service.MarshalPayload(payload)
	if err != nil {
		panic(err)
	}
	hash, err := service.PayloadHash(payload)
	if err != nil {
		panic(err)
	}

	fmt.Println(service.CodecName())
	fmt.Println(len(encoded) > 0)
	fmt.Println(len(hash))
	// Output:
	// pre-secp256k1-ecies-aesgcm-v1
	// true
	// 32
}
