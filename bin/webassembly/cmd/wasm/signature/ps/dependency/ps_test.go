package dependency_test

import (
	"testing"
)

func TestPs(t *testing.T) {

	var mes SecretKey
	mes.SetByRand()

	var sk SecretKey
	sk.SetByRand()
	pk := sk.GetPublicKey()

	var sign Sign
	sign = *sk.Sign(mes.Serialize()[0])

	result := sign.Verify(pk, mes.Serialize()[0])

	t.Log("Verify result:", result)
}
