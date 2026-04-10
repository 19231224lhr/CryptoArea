package post_test

import (
	"fmt"

	"github.com/19231224lhr/CryptoArea/crypto/protocol/post"
)

func Example() {
	service := post.MustNewService(post.WithProfile(post.ProfileLegacyCompatV1))
	challengeMaterial := &post.ChallengeMaterial{
		Commitment: []byte("commitment-root"),
		TimeAnchor: []byte("time-anchor"),
		Nonce:      []byte{0x01, 0x02, 0x03},
		Context:    []byte("post-context"),
		Metadata:   []byte("meta"),
	}
	challenge, err := service.GenerateChallenge(challengeMaterial)
	if err != nil {
		panic(err)
	}
	proofMaterial := &post.ProofMaterial{
		Challenge:        challenge,
		Witness:          []byte("witness-bytes"),
		AuthenticatorKey: []byte("authenticator-key-1234567890"),
		Metadata:         []byte("proof-meta"),
	}
	proof, err := service.Prove(proofMaterial)
	if err != nil {
		panic(err)
	}
	result, err := service.Verify(&post.VerificationInput{
		Challenge:        challenge,
		Proof:            proof,
		Witness:          proofMaterial.Witness,
		AuthenticatorKey: proofMaterial.AuthenticatorKey,
	})
	if err != nil {
		panic(err)
	}

	fmt.Println(service.Profile())
	fmt.Println(result.Valid)
	fmt.Println(len(proof.ResponseDigest) > 0)
	// Output:
	// post-legacycompat-v1
	// true
	// true
}
