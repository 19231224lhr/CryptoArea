//go:build amd64 && !generic
// +build amd64,!generic

package bn254

import "golang.org/x/sys/cpu"

func init() {
	if !cpu.X86.HasADX || !cpu.X86.HasBMI2 {
		mul = mulNoADX
	}
}

var mul func(c, a, b *Fe) = mulNoADX

func square(c, a *Fe) {
	mul(c, a, a)
}

func neg(c, a *Fe) {
	if a.isZero() {
		c.set(a)
	} else {
		_neg(c, a)
	}
}

//go:noescape
func add(c, a, b *Fe)

//go:noescape
func addAssign(a, b *Fe)

//go:noescape
func laddAssign(a, b *Fe)

//go:noescape
func sub(c, a, b *Fe)

//go:noescape
func subAssign(a, b *Fe)

//go:noescape
func lsubAssign(a, b *Fe) uint64

//go:noescape
func _neg(c, a *Fe)

//go:noescape
func double(c, a *Fe)

//go:noescape
func doubleAssign(a *Fe)

//go:noescape
func mulNoADX(c, a, b *Fe)

//go:noescape
func mulADX(c, a, b *Fe)
