package dependency_test

import (
	"testing"
)

func TestPsKey(t *testing.T) {

	t.Log("Key test start.")
	t.Log("Seckey test start.")

	var sk, sk2 SecretKey
	sk.SetByRand()
	t.Log("Seckey gen test done.")

	str := sk.Serialize()
	sk2.Deserialize(str)
	if sk.IsEqual(&sk2) {
		t.Log("Seckey serialize test done.")
	} else {
		t.Log("Seckey serialize fail.")
	}

	var pk, pk2 PublicKey
	pk = *sk.GetPublicKey()
	t.Log("Pubkey gen test done.")

	str = pk.Serialize()
	pk2.Deserialize(str)
	if pk.IsEqual(&pk2) {
		t.Log("Pubkey serialize test done.")
	} else {
		t.Log("Pubkey serialize fail.")
	}

	var sig, sig2 Sign
	sig = *sk.Sign("test")
	t.Log("Sign gen test done.")

	str = sig.Serialize()
	sig2.Deserialize(str)
	if pk.IsEqual(&pk2) {
		t.Log("Sign serialize test done.")
	} else {
		t.Log("Sign serialize fail.")
	}
}
