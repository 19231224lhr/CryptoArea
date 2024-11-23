package dependency

import "C"
import (
	"blockchain-crypto/hash/sha256"
	pbc_go "blockchain-crypto/signature/lib_sig/pbc_go"
	"log"
	"os"
	"path"
	"runtime"
)

// PS签名需要的是type3的配对
// 原文引用了：Galbraith S D, Paterson K G, Smart N P. Pairings for cryptographers[J]. Discrete Applied Mathematics, 2008, 156(16): 3113-3121.
// 对type3的描述：in type 3, G1≠G2 and no efficiently computable homomorphism exists between G1 and G2, in either direction.
// 即：G1和G2不是同一个群，也不存在高效的同态算法
//
// 而pbc库的配对分类是type ABCDEFG，没有明确的分类标准（pbc中type BC未实现）
// 原文中并没有给出具体的配对和曲线选择方法，我按照文中的引文10，其中提到了Constructing pairing-friendly elliptic curves with embedding degree 10
// 所以我认为应该选择pbc中相对应的type G。但是这个type因为我所不能理解的原因而不能工作（报错：元素来自不匹配的代数结构，该报错在pbcgo的example bls签名中也报，所以我觉得不是我代码写错了）
// 另外由于未知的原因，将生成的曲线参数控制台输出后再读入会报错（提示曲线参数无效），不知道如何解决只能每次现生成参数
// const params = "\ntype a\nq 253564097938842104234446785202937183738109574148072383880150574239276557487443\n6590537441280049734700746445433508718769763804791357096685791623061154111691\nh 173495596215628395598725281465451594566099799690058713694127255924154856415539\n9139544115954942596334411572\nr 1461501637330902918203607461463827683388751347711\nexp2 160\nexp1 86\nsign1 -1\nsign0 -1\n"

// SecretKey --
type SecretKey struct {
	x []byte
	y []byte
	g []byte
}

// 获取当前执行文件绝对路径（go run）
func getCurrentAbPathByCaller() string {
	var abPath string
	_, filename, _, ok := runtime.Caller(0)
	if ok {
		abPath = path.Dir(filename)
	}
	return abPath
}

// Serialize --
func (sec *SecretKey) Serialize() []string {
	result := make([]string, 3)
	result[0] = string(sec.x)
	result[1] = string(sec.y)
	result[2] = string(sec.g)
	return result
}

// Deserialize --
func (sec *SecretKey) Deserialize(buf []string) {
	f, err := os.ReadFile(getCurrentAbPathByCaller() + "/curveparams")
	if err != nil {
		log.Printf("读取文件失败")
	}
	params := string(f)
	pairing, _ := pbc_go.NewPairingFromString(params)
	x := pairing.NewZr().SetBytes([]byte(buf[0]))
	y := pairing.NewZr().SetBytes([]byte(buf[1]))
	g := pairing.NewG2().SetBytes([]byte(buf[2]))
	sec.x = x.Bytes()
	sec.y = y.Bytes()
	sec.g = g.Bytes()
}

// IsEqual --
func (sec *SecretKey) IsEqual(rhs *SecretKey) bool {
	return string(sec.x) == string(rhs.x) && string(sec.y) == string(rhs.y) && string(sec.g) == string(rhs.g)
}

// SetByRand --
func (sec *SecretKey) SetByRand() {
	f, err := os.ReadFile(getCurrentAbPathByCaller() + "/curveparams")
	if err != nil {
		log.Printf("读取文件失败")
	}
	params := string(f)
	para, _ := pbc_go.NewParamsFromString(params)
	pairing := para.NewPairing()
	sec.x = pairing.NewZr().Rand().Bytes()
	sec.y = pairing.NewZr().Rand().Bytes()
	sec.g = pairing.NewG2().Rand().Bytes()
}

// PublicKey --
type PublicKey struct {
	g []byte
	X []byte
	Y []byte
}

// Serialize --
func (pub *PublicKey) Serialize() []string {
	result := make([]string, 3)
	result[0] = string(pub.g)
	result[1] = string(pub.X)
	result[2] = string(pub.Y)
	return result
}

// Deserialize --
func (pub *PublicKey) Deserialize(buf []string) {
	f, err := os.ReadFile(getCurrentAbPathByCaller() + "/curveparams")
	if err != nil {
		log.Printf("读取文件失败")
	}
	params := string(f)
	pairing, _ := pbc_go.NewPairingFromString(params)
	g := pairing.NewG2().SetBytes([]byte(buf[0]))
	X := pairing.NewG2().SetBytes([]byte(buf[1]))
	Y := pairing.NewG2().SetBytes([]byte(buf[2]))
	pub.g = g.Bytes()
	pub.X = X.Bytes()
	pub.Y = Y.Bytes()
}

// IsEqual --
func (pub *PublicKey) IsEqual(rhs *PublicKey) bool {
	return string(pub.g) == string(rhs.g) && string(pub.X) == string(rhs.X) && string(pub.Y) == string(rhs.Y)
}

// Sign  --
type Sign struct {
	sgm1 []byte
	sgm2 []byte
}

// Serialize --
func (sign *Sign) Serialize() []string {
	result := make([]string, 2)
	result[0] = string(sign.sgm1)
	result[1] = string(sign.sgm2)
	return result
}

// Deserialize --
func (sign *Sign) Deserialize(buf []string) {
	f, err := os.ReadFile(getCurrentAbPathByCaller() + "/curveparams")
	if err != nil {
		log.Printf("读取文件失败")
	}
	params := string(f)
	pairing, _ := pbc_go.NewPairingFromString(params)
	sgm1 := pairing.NewG1().SetBytes([]byte(buf[0]))
	sgm2 := pairing.NewG1().SetBytes([]byte(buf[1]))
	sign.sgm1 = sgm1.Bytes()
	sign.sgm2 = sgm2.Bytes()
}

// IsEqual --
func (sign *Sign) IsEqual(rhs *Sign) bool {
	return string(sign.sgm1) == string(rhs.sgm1) && string(sign.sgm2) == string(rhs.sgm2)
}

// GetPublicKey --
func (sec *SecretKey) GetPublicKey() (pub *PublicKey) {
	f, err := os.ReadFile(getCurrentAbPathByCaller() + "/curveparams")
	if err != nil {
		log.Printf("读取文件失败")
	}
	params := string(f)
	pub = new(PublicKey)
	pairing, _ := pbc_go.NewPairingFromString(params)
	pub.g = sec.g
	pub.X = pairing.NewG2().PowZn(pairing.NewG2().SetBytes(sec.g), pairing.NewZr().SetBytes(sec.x)).Bytes()
	pub.Y = pairing.NewG2().PowZn(pairing.NewG2().SetBytes(sec.g), pairing.NewZr().SetBytes(sec.y)).Bytes()
	return pub
}

// Sign --
func (sec *SecretKey) Sign(m string) (sign *Sign) {
	f, err := os.ReadFile(getCurrentAbPathByCaller() + "/curveparams")
	if err != nil {
		log.Printf("读取文件失败")
	}
	params := string(f)
	sign = new(Sign)
	pairing, _ := pbc_go.NewPairingFromString(params)
	mes := pairing.NewZr().SetFromStringHash(m, sha256.New())
	xym := pairing.NewZr().Mul(pairing.NewZr().SetBytes(sec.y), mes)
	xym.Add(xym, pairing.NewZr().SetBytes(sec.x))
	h := pairing.NewG1().Rand()
	sign.sgm1 = h.Bytes()
	hxym := pairing.NewG1().PowZn(h, xym)
	sign.sgm2 = hxym.Bytes()
	return sign
}

// Verify --
func (sign *Sign) Verify(pub *PublicKey, m string) bool {
	f, err := os.ReadFile(getCurrentAbPathByCaller() + "/curveparams")
	if err != nil {
		log.Printf("读取文件失败")
	}
	params := string(f)
	pairing, _ := pbc_go.NewPairingFromString(params)
	mes := pairing.NewZr().SetFromStringHash(m, sha256.New())
	temp := pairing.NewG2().PowZn(pairing.NewG2().SetBytes(pub.Y), mes)
	temp.Mul(temp, pairing.NewG2().SetBytes(pub.X))
	el := pairing.NewGT().Pair(pairing.NewG1().SetBytes(sign.sgm1), temp)
	er := pairing.NewGT().Pair(pairing.NewG1().SetBytes(sign.sgm2), pairing.NewG2().SetBytes(pub.g))
	return el.Equals(er)
}
