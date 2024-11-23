package groupsig

import (
	"blockchain-crypto/signature/bls/bn254/dependency/bls"
)

// Init --
func Init(curve int) {
	err := bls.Init(curve)
	if err != nil {
		panic("groupsig.Init")
	}
	curveOrder.SetString(bls.GetCurveOrder(), 10)
	fieldOrder.SetString(bls.GetFieldOrder(), 10)
	bitLength = curveOrder.BitLen()
}
