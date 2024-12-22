package bn254

import (
	"crypto/rand"
	"crypto/sha256"
	"io"
	"math/big"
)

type Fr big.Int

var (
	zeroBig = big.NewInt(0)
	oneBig  = big.NewInt(1)
)

func NewFr() *Fr {
	return (*Fr)(new(big.Int).Set(zeroBig))
}

func (e *Fr) Set(e2 *Fr) *Fr {
	(*big.Int)(e).Set((*big.Int)(e2))
	return e
}

func (e *Fr) Zero() *Fr {
	(*big.Int)(e).Set(zeroBig)
	return e
}

func (e *Fr) One() *Fr {
	(*big.Int)(e).Set(oneBig)
	return e
}

func (e *Fr) Rand(r io.Reader) (*Fr, error) {
	bi, err := rand.Int(r, qBig)
	if err != nil {
		return nil, err
	}
	(*big.Int)(e).Set(bi)
	return e, nil
}

func (e *Fr) FromBig(in *big.Int) *Fr {
	return (*Fr)(new(big.Int).Mod(in, qBig))
}

func (e *Fr) ToBig() *big.Int {
	return (*big.Int)(e)
}

func FrFromInt(in int) *Fr {
	return (*Fr)(new(big.Int).Mod(big.NewInt(int64(in)), qBig))
}

func FrFromUInt32(in uint32) *Fr {
	return (*Fr)(new(big.Int).Mod(big.NewInt(int64(in)), qBig))
}

func (e *Fr) BitLen() int {
	return (*big.Int)(e).BitLen()
}

func (e *Fr) Bit(at int) uint {
	return (*big.Int)(e).Bit(at)
}

func (e *Fr) FromBytes(buf []byte) *Fr {
	return (*Fr)((*big.Int)(e).SetBytes(buf))
}

func (e *Fr) ToBytes() []byte {
	return (*big.Int)(e).Bytes()
}

func (e *Fr) String() string {
	return (*big.Int)(e).String()
}

func (e *Fr) IsZero() bool {
	return (*big.Int)(e).Cmp(zeroBig) == 0
}

func (e *Fr) IsOne() bool {
	return (*big.Int)(e).Cmp(oneBig) == 0
}

func (e *Fr) Equal(e2 *Fr) bool {
	return (*big.Int)(e).Cmp((*big.Int)(e2)) == 0
}

func (e *Fr) Add(a, b *Fr) *Fr {
	(*big.Int)(e).Add((*big.Int)(a), (*big.Int)(b)).Mod((*big.Int)(e), qBig)
	return e
}

func (e *Fr) Sub(a, b *Fr) *Fr {
	(*big.Int)(e).Sub((*big.Int)(a), (*big.Int)(b)).Mod((*big.Int)(e), qBig)
	return e
}

func (e *Fr) Neg(a *Fr) *Fr {
	(*big.Int)(e).Neg((*big.Int)(a)).Mod((*big.Int)(e), qBig)
	return e
}

func (e *Fr) Mul(a, b *Fr) *Fr {
	(*big.Int)(e).Mul((*big.Int)(a), (*big.Int)(b)).Mod((*big.Int)(e), qBig)
	return e
}

func (e *Fr) Exp(a *Fr, ee *big.Int) *Fr {
	(*big.Int)(e).Exp((*big.Int)(a), ee, qBig)
	return e
}

func (e *Fr) Inverse(a *Fr) *Fr {
	(*big.Int)(e).ModInverse((*big.Int)(a), qBig)
	return e
}

func HashToFr(input []byte) *Fr {
	h := sha256.New()
	h.Write(input)
	output := h.Sum(nil)
	return NewFr().FromBytes(output)
}
