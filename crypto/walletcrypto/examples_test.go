package walletcrypto_test

import (
	"fmt"

	"github.com/19231224lhr/CryptoArea/crypto/walletcrypto"
)

func ExampleGenerateKeyPair() {
	kp, err := walletcrypto.GenerateKeyPair(walletcrypto.AlgECDSA)
	if err != nil {
		panic(err)
	}

	msg := []byte("example-message")
	sig, err := walletcrypto.SignMessage(walletcrypto.AlgECDSA, kp.PrivateKey, msg)
	if err != nil {
		panic(err)
	}
	ok, err := walletcrypto.VerifyMessage(walletcrypto.AlgECDSA, kp.PublicKey, msg, sig)
	if err != nil {
		panic(err)
	}

	fmt.Println(ok)
	// Output:
	// true
}

func ExampleSeedChain() {
	sc, err := walletcrypto.NewSeedChainFromSeed(walletcrypto.AlgECDSA, []byte("example-seedchain-root"), 3)
	if err != nil {
		panic(err)
	}

	_, _, step, nextAnchor, err := sc.ConsumeSeed()
	if err != nil {
		panic(err)
	}

	fmt.Println(step, len(nextAnchor) > 0, sc.RemainingSteps())
	// Output:
	// 3 true 2
}
