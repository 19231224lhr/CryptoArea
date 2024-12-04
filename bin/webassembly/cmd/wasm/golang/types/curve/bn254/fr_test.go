package bn254

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
)

func TestFr_FromBig(t *testing.T) {
	fr := NewFr()
	fmt.Println(fr)
	fmt.Println(new(big.Int))
	fr.FromBig(big.NewInt(2))
	fmt.Println(fr)
}

func TestFrAdditionProperties(t *testing.T) {
	for i := 0; i < fuz; i++ {
		zero := new(Fr)
		a, _ := new(Fr).Rand(rand.Reader)
		b, _ := new(Fr).Rand(rand.Reader)
		c1, c2 := new(Fr), new(Fr)
		c1.Add(a, zero)
		if !c1.Equal(a) {
			t.Fatal("a + 0 == a")
		}
		c1.Sub(a, zero)
		if !c1.Equal(a) {
			t.Fatal("a - 0 == a")
		}
		c1.Mul(FrFromInt(2), zero)
		if !c1.Equal(zero) {
			t.Fatal("2 * 0 == 0")
		}
		c1.Neg(zero)
		if !c1.Equal(zero) {
			t.Fatal("-0 == 0")
		}
		c1.Sub(zero, a)
		c2.Neg(a)
		if !c1.Equal(c2) {
			t.Fatal("0-a == -a")
		}
		c1.Mul(FrFromInt(2), a)
		c2.Add(a, a)
		if !c1.Equal(c2) {
			t.Fatal("2 * a == a + a")
		}
		c1.Add(a, b)
		c2.Add(b, a)
		if !c1.Equal(c2) {
			t.Fatal("a + b = b + a")
		}
		c1.Sub(a, b)
		c2.Sub(b, a)
		c2.Neg(c2)
		if !c1.Equal(c2) {
			t.Fatal("a - b = - ( b - a )")
		}
		c0, _ := new(Fr).Rand(rand.Reader)
		c1.Add(a, b)
		c1.Add(c1, c0)
		c2.Add(a, c0)
		c2.Add(c2, b)
		if !c1.Equal(c2) {
			t.Fatal("(a + b) + c == (a + c ) + b")
		}
		c1.Sub(a, b)
		c1.Sub(c1, c0)
		c2.Sub(a, c0)
		c2.Sub(c2, b)
		if !c1.Equal(c2) {
			t.Fatal("(a - b) - c == (a - c ) -b")
		}
	}
}

func TestFrMultiplicationProperties(t *testing.T) {
	for i := 0; i < fuz; i++ {
		a, _ := new(Fr).Rand(rand.Reader)
		b, _ := new(Fr).Rand(rand.Reader)
		zero, one := new(Fr).Zero(), new(Fr).One()
		c1, c2 := new(Fr), new(Fr)
		c1.Mul(a, zero)
		if !c1.Equal(zero) {
			t.Fatal("a * 0 == 0")
		}
		c1.Mul(a, one)
		if !c1.Equal(a) {
			t.Fatal("a * 1 == a")
		}
		c1.Mul(a, b)
		c2.Mul(b, a)
		if !c1.Equal(c2) {
			t.Fatal("a * b == b * a")
		}
		c0, _ := new(Fr).Rand(rand.Reader)
		c1.Mul(a, b)
		c1.Mul(c1, c0)
		c2.Mul(c0, b)
		c2.Mul(c2, a)
		if !c1.Equal(c2) {
			t.Fatal("(a * b) * c == (a * c) * b")
		}
		a.Mul(zero, zero)
		if !a.Equal(zero) {
			t.Fatal("0^2 == 0")
		}
		a.Mul(one, one)
		if !a.Equal(one) {
			t.Fatal("1^2 == 1")
		}
	}
}

func TestFrExponentiation(t *testing.T) {
	for i := 0; i < fuz; i++ {
		a, _ := new(Fr).Rand(rand.Reader)
		u := new(Fr)
		u.Exp(a, big.NewInt(0))
		if !u.Equal(new(Fr).One()) {
			t.Fatal("a^0 == 1")
		}
		u.Exp(a, big.NewInt(1))
		if !u.Equal(a) {
			t.Fatal("a^1 == a")
		}
		v := new(Fr)
		u.Mul(a, a)
		u.Mul(u, u)
		u.Mul(u, u)
		v.Exp(a, big.NewInt(8))
		if !u.Equal(v) {
			t.Fatal("((a^2)^2)^2 == a^8")
		}
		u.Exp(a, qBig)
		if !u.Equal(a) {
			t.Fatal("a^p == a")
		}
		qMinus1 := new(big.Int).Sub(qBig, big.NewInt(1))
		u.Exp(a, qMinus1)
		if !u.Equal(new(Fr).One()) {
			t.Fatal("a^(p-1) == 1")
		}
	}
}

func TestFrInversion(t *testing.T) {
	for i := 0; i < fuz; i++ {
		u := new(Fr)
		zero, one := new(Fr).Zero(), new(Fr).One()
		u.Inverse(zero)
		if !u.Equal(zero) {
			t.Fatal("(0^-1) == 0)")
		}
		u.Inverse(one)
		if !u.Equal(new(Fr).One()) {
			t.Fatal("(1^-1) == 1)")
		}
		a, _ := new(Fr).Rand(rand.Reader)
		u.Inverse(a)
		u.Mul(u, a)
		if !u.Equal(new(Fr).One()) {
			t.Fatal("a * a^-1 == 1")
		}
		v := new(Fr)
		z := new(big.Int)
		u.Exp(a, z.Sub(qBig, big.NewInt(2)))
		v.Inverse(a)
		if !v.Equal(u) {
			t.Fatal("a^(p-2) == a^-1")
		}
	}
}
