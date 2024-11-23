package bn254

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
)

type Fe /***			***/ [4]uint64

type fe2 /**			***/ [2]Fe

type fe6 /**			***/ [3]fe2

type fe12 /**			***/ [2]fe6

func (fe *Fe) setBytes(in []byte) *Fe {
	size := 32
	l := len(in)
	if l >= size {
		l = size
	}
	padded := make([]byte, size)
	copy(padded[size-l:], in[:])
	var a int
	for i := 0; i < 4; i++ {
		a = size - i*8
		fe[i] = uint64(padded[a-1]) | uint64(padded[a-2])<<8 |
			uint64(padded[a-3])<<16 | uint64(padded[a-4])<<24 |
			uint64(padded[a-5])<<32 | uint64(padded[a-6])<<40 |
			uint64(padded[a-7])<<48 | uint64(padded[a-8])<<56
	}
	return fe
}

func (fe *Fe) setBig(a *big.Int) *Fe {
	return fe.setBytes(a.Bytes())
}

func (fe *Fe) setString(s string) (*Fe, error) {
	if s[:2] == "0x" {
		s = s[2:]
	}
	bytes, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return fe.setBytes(bytes), nil
}

func (fe *Fe) set(fe2 *Fe) *Fe {
	fe[0] = fe2[0]
	fe[1] = fe2[1]
	fe[2] = fe2[2]
	fe[3] = fe2[3]
	return fe
}

func (fe *Fe) Bytes() []byte {
	out := make([]byte, 32)
	var a int
	for i := 0; i < 4; i++ {
		a = 32 - i*8
		out[a-1] = byte(fe[i])
		out[a-2] = byte(fe[i] >> 8)
		out[a-3] = byte(fe[i] >> 16)
		out[a-4] = byte(fe[i] >> 24)
		out[a-5] = byte(fe[i] >> 32)
		out[a-6] = byte(fe[i] >> 40)
		out[a-7] = byte(fe[i] >> 48)
		out[a-8] = byte(fe[i] >> 56)
	}
	return out
}

func (fe *Fe) big() *big.Int {
	return new(big.Int).SetBytes(fe.Bytes())
}

func (fe *Fe) string() (s string) {
	for i := 3; i >= 0; i-- {
		s = fmt.Sprintf("%s%16.16x", s, fe[i])
	}
	return "0x" + s
}

func (fe *Fe) zero() *Fe {
	fe[0] = 0
	fe[1] = 0
	fe[2] = 0
	fe[3] = 0
	return fe
}

func (fe *Fe) One() *Fe {
	return fe.set(r1)
}

func (fe *Fe) Rand(r io.Reader) (*Fe, error) {
	bi, err := rand.Int(r, modulus.big())
	if err != nil {
		return nil, err
	}
	return fe.setBig(bi), nil
}

func (fe *Fe) isValid() bool {
	return fe.cmp(&modulus) == -1
}

func (fe *Fe) isOdd() bool {
	var mask uint64 = 1
	return fe[0]&mask != 0
}

func (fe *Fe) isEven() bool {
	var mask uint64 = 1
	return fe[0]&mask == 0
}

func (fe *Fe) isZero() bool {
	return (fe[3] | fe[2] | fe[1] | fe[0]) == 0
}

func (fe *Fe) isOne() bool {
	return fe.equal(r1)
}

func (fe *Fe) cmp(fe2 *Fe) int {
	for i := 3; i >= 0; i-- {
		if fe[i] > fe2[i] {
			return 1
		} else if fe[i] < fe2[i] {
			return -1
		}
	}
	return 0
}

func (fe *Fe) equal(fe2 *Fe) bool {
	return fe2[0] == fe[0] && fe2[1] == fe[1] && fe2[2] == fe[2] && fe2[3] == fe[3]
}

func (e *Fe) signBE() bool {
	negZ, z := new(Fe), new(Fe)
	fromMont(z, e)
	neg(negZ, z)
	return negZ.cmp(z) > -1
}

func (e *Fe) sign() bool {
	r := new(Fe)
	fromMont(r, e)
	return r[0]&1 == 0
}

func (fe *Fe) div2(e uint64) {
	fe[0] = fe[0]>>1 | fe[1]<<63
	fe[1] = fe[1]>>1 | fe[2]<<63
	fe[2] = fe[2]>>1 | fe[3]<<63
	fe[3] = fe[3]>>1 | e<<63
}

func (fe *Fe) mul2() uint64 {
	e := fe[3] >> 63
	fe[3] = fe[3]<<1 | fe[2]>>63
	fe[2] = fe[2]<<1 | fe[1]>>63
	fe[1] = fe[1]<<1 | fe[0]>>63
	fe[0] = fe[0] << 1
	return e
}

func (e *fe2) zero() *fe2 {
	e[0].zero()
	e[1].zero()
	return e
}

func (e *fe2) one() *fe2 {
	e[0].One()
	e[1].zero()
	return e
}

func (e *fe2) set(e2 *fe2) *fe2 {
	e[0].set(&e2[0])
	e[1].set(&e2[1])
	return e
}

func (e *fe2) rand(r io.Reader) (*fe2, error) {
	a0, err := new(Fe).Rand(r)
	if err != nil {
		return nil, err
	}
	a1, err := new(Fe).Rand(r)
	if err != nil {
		return nil, err
	}
	return &fe2{*a0, *a1}, nil
}

func (e *fe2) isOne() bool {
	return e[0].isOne() && e[1].isZero()
}

func (e *fe2) isZero() bool {
	return e[0].isZero() && e[1].isZero()
}

func (e *fe2) equal(e2 *fe2) bool {
	return e[0].equal(&e2[0]) && e[1].equal(&e2[1])
}

func (e *fe2) signBE() bool {
	if !e[1].isZero() {
		return e[1].signBE()
	}
	return e[0].signBE()
}

func (e *fe2) sign() bool {
	r := new(Fe)
	if !e[0].isZero() {
		fromMont(r, &e[0])
		return r[0]&1 == 0
	}
	fromMont(r, &e[1])
	return r[0]&1 == 0
}

func (e *fe6) zero() *fe6 {
	e[0].zero()
	e[1].zero()
	e[2].zero()
	return e
}

func (e *fe6) one() *fe6 {
	e[0].one()
	e[1].zero()
	e[2].zero()
	return e
}

func (e *fe6) set(e2 *fe6) *fe6 {
	e[0].set(&e2[0])
	e[1].set(&e2[1])
	e[2].set(&e2[2])
	return e
}

func (e *fe6) rand(r io.Reader) (*fe6, error) {
	a0, err := new(fe2).rand(r)
	if err != nil {
		return nil, err
	}
	a1, err := new(fe2).rand(r)
	if err != nil {
		return nil, err
	}
	a2, err := new(fe2).rand(r)
	if err != nil {
		return nil, err
	}
	return &fe6{*a0, *a1, *a2}, nil
}

func (e *fe6) isOne() bool {
	return e[0].isOne() && e[1].isZero() && e[2].isZero()
}

func (e *fe6) isZero() bool {
	return e[0].isZero() && e[1].isZero() && e[2].isZero()
}

func (e *fe6) equal(e2 *fe6) bool {
	return e[0].equal(&e2[0]) && e[1].equal(&e2[1]) && e[2].equal(&e2[2])
}

func (e *fe12) zero() *fe12 {
	e[0].zero()
	e[1].zero()
	return e
}

func (e *fe12) one() *fe12 {
	e[0].one()
	e[1].zero()
	return e
}

func (e *fe12) set(e2 *fe12) *fe12 {
	e[0].set(&e2[0])
	e[1].set(&e2[1])
	return e
}

func (e *fe12) rand(r io.Reader) (*fe12, error) {
	a0, err := new(fe6).rand(r)
	if err != nil {
		return nil, err
	}
	a1, err := new(fe6).rand(r)
	if err != nil {
		return nil, err
	}
	return &fe12{*a0, *a1}, nil
}

func (e *fe12) isOne() bool {
	return e[0].isOne() && e[1].isZero()
}

func (e *fe12) isZero() bool {
	return e[0].isZero() && e[1].isZero()
}

func (e *fe12) equal(e2 *fe12) bool {
	return e[0].equal(&e2[0]) && e[1].equal(&e2[1])
}
