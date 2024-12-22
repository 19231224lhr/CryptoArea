package dependency

import (
	"blockchain-crypto/hash"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"

	"blockchain-crypto/signature/ec_schnorr/dependency/common"
)

var (
	GenerateSignatureError = errors.New("Failed to generate the schnorr signature, s = 0 happened.")
	EmptyMessageError      = errors.New("The message to be signed should not be empty")
)

// 通过这个数据结构来生成私钥的json
type ECDSAPrivateKey struct {
	Curvname string
	X, Y, D  *big.Int
}

// 通过这个数据结构来生成公钥的json
type ECDSAPublicKey struct {
	Curvname string
	X, Y     *big.Int
}

func getNewEcdsaPrivateKey(k *ecdsa.PrivateKey) *ECDSAPrivateKey {
	key := new(ECDSAPrivateKey)
	key.Curvname = k.Params().Name
	key.D = k.D
	key.X = k.X
	key.Y = k.Y

	return key
}

func getNewEcdsaPublicKey(k *ecdsa.PrivateKey) *ECDSAPublicKey {
	key := new(ECDSAPublicKey)
	key.Curvname = k.Params().Name
	key.X = k.X
	key.Y = k.Y

	return key
}

func getNewEcdsaPublicKeyFromPublicKey(k *ecdsa.PublicKey) *ECDSAPublicKey {
	key := new(ECDSAPublicKey)
	key.Curvname = k.Params().Name
	key.X = k.X
	key.Y = k.Y

	return key
}

// 获得私钥所对应的的json
func GetEcdsaPrivateKeyJsonFormat(k *ecdsa.PrivateKey) (string, error) {
	// 转换为自定义的数据结构
	key := getNewEcdsaPrivateKey(k)

	// 转换json
	data, err := json.Marshal(key)

	return string(data), err
}

// 获得公钥所对应的的json
func GetEcdsaPublicKeyJsonFormat(k *ecdsa.PrivateKey) (string, error) {
	// 转换为自定义的数据结构
	key := getNewEcdsaPublicKey(k)

	// 转换json
	data, err := json.Marshal(key)

	return string(data), err
}

// 获得公钥所对应的的json
func GetEcdsaPublicKeyJsonFormatFromPublicKey(k *ecdsa.PublicKey) (string, error) {
	// 转换为自定义的数据结构
	key := getNewEcdsaPublicKeyFromPublicKey(k)

	// 转换json
	data, err := json.Marshal(key)

	return string(data), err
}

// 从json格式私钥内容字符串产生ECC私钥
func GetEcdsaPrivateKeyFromJsonStr(keyStr string) (*ecdsa.PrivateKey, error) {
	jsonBytes := []byte(keyStr)
	return GetEcdsaPrivateKeyFromJson(jsonBytes)
}

func GetEcdsaPrivateKeyFromJson(jsonContent []byte) (*ecdsa.PrivateKey, error) {
	privateKey := new(ECDSAPrivateKey)
	err := json.Unmarshal(jsonContent, privateKey)
	if err != nil {
		return nil, err
	}
	if privateKey.Curvname != "P-256" {
		print("curve [%v] is not supported yet.", privateKey.Curvname)
		err = fmt.Errorf("curve [%v] is not supported yet.", privateKey.Curvname)
		return nil, err
	}
	ecdsaPrivateKey := &ecdsa.PrivateKey{}
	ecdsaPrivateKey.PublicKey.Curve = elliptic.P256()
	ecdsaPrivateKey.X = privateKey.X
	ecdsaPrivateKey.Y = privateKey.Y
	ecdsaPrivateKey.D = privateKey.D

	return ecdsaPrivateKey, nil
}

// 从json格式公钥内容字符串产生ECC公钥
func GetEcdsaPublicKeyFromJsonStr(keyStr string) (*ecdsa.PublicKey, error) {
	jsonBytes := []byte(keyStr)
	return GetEcdsaPublicKeyFromJson(jsonBytes)
}

func GetEcdsaPublicKeyFromJson(jsonContent []byte) (*ecdsa.PublicKey, error) {
	publicKey := new(ECDSAPublicKey)
	err := json.Unmarshal(jsonContent, publicKey)
	if err != nil {
		return nil, err // json有问题
	}
	if publicKey.Curvname != "P-256" {
		print("curve [%v] is not supported yet.", publicKey.Curvname)
		err = fmt.Errorf("curve [%v] is not supported yet.", publicKey.Curvname)
		return nil, err
	}
	ecdsaPublicKey := &ecdsa.PublicKey{}
	ecdsaPublicKey.Curve = elliptic.P256()
	ecdsaPublicKey.X = publicKey.X
	ecdsaPublicKey.Y = publicKey.Y

	return ecdsaPublicKey, nil
}

// 默认的KeyGen
func GenerateKey(c elliptic.Curve) (*ecdsa.PrivateKey, error) {
	SeedSize := 32
	seed := make([]byte, SeedSize)
	rand := cryptorand.Reader
	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, err
	}
	return GenerateKeyBySeed(c, seed)
}

// GenerateKey generates a public and private key pair.
func GenerateKeyBySeed(c elliptic.Curve, seed []byte) (*ecdsa.PrivateKey, error) {
	k, err := randFieldElement(c, seed)
	if err != nil {
		return nil, err
	}

	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv, nil
}

var one = new(big.Int).SetInt64(1)

// randFieldElement returns a random element of the field underlying the given
// curve using the procedure given in [NSA] A.2.1.
func randFieldElement(c elliptic.Curve, entropy []byte) (k *big.Int, err error) {
	params := c.Params()
	//	b := make([]byte, params.BitSize/8+8)
	//	_, err = io.ReadFull(rand, b)
	//	if err != nil {
	//		return
	//	}

	//	k = new(big.Int).SetBytes(b)
	k = new(big.Int).SetBytes(entropy)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

// Schnorr signatures use a particular function, defined as:
// H'(m, s, e) = H(m || s * G - e * P)
//
// H is a hash function, for instance SHA256 or SM3.
// s and e are 2 numbers forming the signature itself.
// m is the message to sign.
// P is the public key.
//
// To verify the signature, check that the result of H'(m, s, e) is equal to e.
// Which means that: H(m || s * G - e * P) = e
//
// It's impossible for the others to find such a pair of (s, e) but the signer himself.
// This is because: P = x * G
// So the signer is able to get this equation: H(m || s * G - e * x * G) = e = H(m || (s - e * x) * G)
// It can be considered as:  H(m || k * G) = e, where k = s - e * x
//
// This is the original process:
// 1. Choose a random number k
// 2. Compute e = H(m || k * G)
// 3. Because k = s - e * x, k and x (the key factor of the private key) are already known, we can compute s
// 4. Now we get the SchnorrSignature (e, s)
//
// Note that there is a potential risk for the private key, which also exists in the ECDSA algorithm:
// "The number k must be random enough."
// If not, say the same k has been used twice or the second k can be predicted by the first k,
// the attacker will be able to retrieve the private key (x)
// This is because:
//  1. If the same k has been used twice:
//     k = s0 - e0 * x = s1 - e1 * x
//
// The attacker knows: x = (s0 - s1) / (e0 - e1)
//
//  2. If the second k1 can be predicted by the first k0:
//     k0 = s0 - e0 * x
//     k1 = s1 - e1 * x
//
// The attacker knows: x = (k1 - k0 + s0 - s1) / (e0 - e1)
//
// So the final process is:
//  1. Compute k = H(m || x)
//     This makes k unpredictable for anyone who do not know x,
//     therefor it's impossible for the attacker to retrive x by breaking the random number generator of the system,
//     which has happend in the Sony PlayStation 3 firmware attack.
//  2. Compute e = H(m || k * G)
//  3. Because k = s - e * x, k and x (the key factor of the private key) are already known,
//     we can compute s = k + e * x
//  4. Now we get the SchnorrSignature (e, s)
func Sign(privateKey *ecdsa.PrivateKey, message []byte) (schnorrSignature []byte, err error) {
	if privateKey == nil {
		return nil, fmt.Errorf("Invalid privateKey. PrivateKey must not be nil.")
	}

	// 1. Compute k = H(m || x)
	k := hash.Hash("sha256", append(message, privateKey.D.Bytes()...))

	// 2. Compute e = H(m || k * G)
	// 2.1 compute k * G
	curve := privateKey.Curve
	x, y := curve.ScalarBaseMult(k)
	// 2.2 compute H(m || k * G)
	e := hash.Hash("sha256", append(message, elliptic.Marshal(curve, x, y)...))

	// 3. k = s - e * x, so we can compute s = k + e * x
	intK := new(big.Int).SetBytes(k)
	intE := new(big.Int).SetBytes(e)

	intS, err := ComputeSByKEX(curve, intK, intE, privateKey.D)
	if err != nil {
		return nil, GenerateSignatureError
	}

	// generate the schnorr signature：(sum(S), R)
	// 生成Schnorr签名：(sum(S), R)
	schnorrSig := &common.SchnorrSignature{
		E: intE,
		S: intS,
	}
	// convert the signature to json format
	// 将签名格式转换json
	sig, err := json.Marshal(schnorrSig)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// Compute s = k + e*x
func ComputeSByKEX(curve elliptic.Curve, k, e, x *big.Int) (*big.Int, error) {
	intS := new(big.Int).Add(k, new(big.Int).Mul(e, x))

	return intS, nil
}

// In order to verify the signature, only need to check the equation:
// H'(m, s, e) = H(m || s * G - e * P) = e
// i.e. whether e is equal to H(m || s * G - e * P)
func Verify(publicKey *ecdsa.PublicKey, sig []byte, message []byte) (valid bool, err error) {
	signature := new(common.SchnorrSignature)
	err = json.Unmarshal(sig, signature)
	if err != nil {
		return false, fmt.Errorf("Failed unmashalling schnorr signature [%s]", err)
	}

	// 1. compute h(m|| s * G - e * P)
	// 1.1 compute s * G
	curve := publicKey.Curve
	x1, y1 := curve.ScalarBaseMult(signature.S.Bytes())

	// 1.2 compute e * P
	x2, y2 := curve.ScalarMult(publicKey.X, publicKey.Y, signature.E.Bytes())

	// 1.3 计算-(e * P)，如果 e * P = (x,y)，则 -(e * P) = (x, -y mod P)
	negativeOne := big.NewInt(-1)
	y2 = new(big.Int).Mod(new(big.Int).Mul(negativeOne, y2), curve.Params().P)

	// 1.4 compute s * G - e * P
	x, y := curve.Add(x1, y1, x2, y2)

	e := hash.Hash("sha256", append(message, elliptic.Marshal(curve, x, y)...))

	intE := new(big.Int).SetBytes(e)

	// 2. check the equation
	//	return bytes.Equal(e, signature.E.Bytes()), nil
	if intE.Cmp(signature.E) != 0 {
		return false, nil
	}
	return true, nil
}
