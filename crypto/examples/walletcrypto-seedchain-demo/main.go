package main

import (
	"fmt"

	"github.com/19231224lhr/CryptoArea/crypto/walletcrypto"
)

func main() {
	// This example uses ECDSA so it can run without cgo. If you want a PQ demo,
	// replace AlgECDSA with AlgPQMLDSA in an environment where pqcgo is enabled.
	chain, err := walletcrypto.NewSeedChain(walletcrypto.AlgECDSA, 4)
	if err != nil {
		panic(err)
	}

	currentAnchor, err := chain.CurrentAnchor()
	if err != nil {
		panic(err)
	}
	fmt.Printf("current step: %d\n", chain.CurrentStep)
	fmt.Printf("current anchor length: %d\n", len(currentAnchor))

	seed, kp, step, nextAnchor, err := chain.ConsumeSeed()
	if err != nil {
		panic(err)
	}
	fmt.Printf("consumed step: %d\n", step)
	fmt.Printf("revealed seed length: %d\n", len(seed))
	fmt.Printf("public key length: %d\n", len(kp.PublicKey))
	fmt.Printf("next anchor length: %d\n", len(nextAnchor))

	message := []byte("walletcrypto-seedchain-demo")
	sig, err := walletcrypto.SignMessage(walletcrypto.AlgECDSA, kp.PrivateKey, message)
	if err != nil {
		panic(err)
	}
	ok, err := walletcrypto.VerifyMessage(walletcrypto.AlgECDSA, kp.PublicKey, message, sig)
	if err != nil {
		panic(err)
	}
	fmt.Printf("verify: %v\n", ok)
}

