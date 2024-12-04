package bn254

import (
	"errors"
	"math/big"
)

func fromBytes(in []byte) (*Fe, error) {
	fe := &Fe{}
	if len(in) != 32 {
		return nil, errors.New("input string should be equal 32 bytes")
	}
	fe.setBytes(in)
	if !fe.isValid() {
		return nil, errors.New("must be less than modulus")
	}
	toMont(fe, fe)
	return fe, nil
}

func from48Bytes(in []byte) (*Fe, error) {
	if len(in) != 48 {
		return nil, errors.New("input string should be equal 48 bytes")
	}
	a0 := make([]byte, 32)
	copy(a0[8:32], in[:24])
	a1 := make([]byte, 32)
	copy(a1[8:32], in[24:])
	e0, err := fromBytes(a0)
	if err != nil {
		return nil, err
	}
	e1, err := fromBytes(a1)
	if err != nil {
		return nil, err
	}
	// F = 2 ^ 192 * res
	F := Fe{
		0xd9e291c2cdd22cd6,
		0xc722ccf2a40f0271,
		0xa49e35d611a2ac87,
		0x2e1043978c993ec8,
	}
	mul(e0, e0, &F)
	add(e1, e1, e0)
	return e1, nil
}

func fromBytesUnchecked(in []byte) (*Fe, error) {
	fe := &Fe{}
	if len(in) != 32 {
		return nil, errors.New("input string should be equal 32 bytes")
	}
	fe.setBytes(in)
	toMont(fe, fe)
	return fe, nil
}

func FromBig(in *big.Int) (*Fe, error) {
	fe := new(Fe).setBig(in)
	if !fe.isValid() {
		return nil, errors.New("invalid input string")
	}
	toMont(fe, fe)
	return fe, nil
}

func fromString(in string) (*Fe, error) {
	fe, err := new(Fe).setString(in)
	if err != nil {
		return nil, err
	}
	if !fe.isValid() {
		return nil, errors.New("invalid input string")
	}
	toMont(fe, fe)
	return fe, nil
}

func toBytes(e *Fe) []byte {
	e2 := new(Fe)
	fromMont(e2, e)
	return e2.Bytes()
}

func ToBig(e *Fe) *big.Int {
	e2 := new(Fe)
	fromMont(e2, e)
	return e2.big()
}

func toString(e *Fe) (s string) {
	e2 := new(Fe)
	fromMont(e2, e)
	return e2.string()
}

func toMont(c, a *Fe) {
	mul(c, a, r2)
}

func fromMont(c, a *Fe) {
	mul(c, a, &Fe{1})
}

func exp(c, a *Fe, e *big.Int) {
	z := new(Fe).set(r1)
	for i := e.BitLen(); i >= 0; i-- {
		mul(z, z, z)
		if e.Bit(i) == 1 {
			mul(z, z, a)
		}
	}
	c.set(z)
}

func inverse(inv, e *Fe) {
	if e.isZero() {
		inv.zero()
		return
	}
	u := new(Fe).set(&modulus)
	v := new(Fe).set(e)
	s := &Fe{1}
	r := &Fe{0}
	var k int
	var z uint64
	var found = false
	// Phase 1
	for i := 0; i < 512; i++ {
		if v.isZero() {
			found = true
			break
		}
		if u.isEven() {
			u.div2(0)
			s.mul2()
		} else if v.isEven() {
			v.div2(0)
			z += r.mul2()
		} else if u.cmp(v) == 1 {
			lsubAssign(u, v)
			u.div2(0)
			laddAssign(r, s)
			s.mul2()
		} else {
			lsubAssign(v, u)
			v.div2(0)
			laddAssign(s, r)
			z += r.mul2()
		}
		k += 1
	}

	if !found {
		inv.zero()
		return
	}

	if k < 254 || k > 254+256 {
		inv.zero()
		return
	}

	if r.cmp(&modulus) != -1 || z > 0 {
		lsubAssign(r, &modulus)
	}
	u.set(&modulus)
	lsubAssign(u, r)

	// Phase 2
	for i := k; i < 256*2; i++ {
		double(u, u)
	}
	inv.set(u)
}

func sqrt(c, a *Fe) bool {
	u, v := new(Fe).set(a), new(Fe)
	exp(c, a, pPlus1Over4)
	square(v, c)
	return u.equal(v)
}

func isQuadraticNonResidue(e *Fe) bool {
	result := new(Fe)
	exp(result, e, pMinus1Over2)
	return !result.isOne()
}

func legendre(e *Fe) int {
	if e.isZero() {
		return 0
	}
	if isQuadraticNonResidue(e) {
		return -1
	}
	return 1
}
