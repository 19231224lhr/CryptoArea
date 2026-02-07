# walletcrypto 中文使用文档

## 0. 仓库总览（crypto-suites）

如果你需要向他人讲清楚“整个项目做什么”，可以先用下面这张结构图：

- `crypto-suites/crypto`
  - 经典密码算法模块（签名、哈希等）
  - 本文档关注的 `walletcrypto` 位于这里
- `crypto-suites/pqcgo`
  - Go 封装的后量子能力（签名 + KEM）
  - 通过 cgo 调用 PQMagic C 库
- `crypto-suites/wasm`
  - wasm 相关封装与 C 测试代码

面向钱包接入时，推荐把 `walletcrypto` 当成主入口，上层业务尽量只依赖这一层。

## 1. 项目定位

`walletcrypto` 是一个面向钱包业务的统一密码接口层，目标是把“钱包真正需要调用的密码能力”收敛到一组稳定 API 中，避免上层项目直接耦合底层多个密码实现细节。

当前它整合了两类能力：

- 经典算法能力（来自 `crypto/signature`）
- 后量子能力（来自 `pqcgo`，底层调用 PQMagic C 库）

它适合用于钱包或账户系统中的：

- 私钥/公钥生成
- 交易签名与验签
- 地址生成
- 私钥加密存储（keystore）
- 哈希/HMAC/随机数等基础密码工具
- 后量子 KEM（共享密钥封装/解封装）

## 2. 目录结构与职责

`walletcrypto` 目录主要文件如下：

- `api.go`
  - 统一签名类接口：`GenerateKeyPair` / `SignMessage` / `VerifyMessage`
  - 算法路由（经典 vs 后量子签名）
- `kem.go`
  - 后量子 KEM 接口：`GenerateKEMKeyPair` / `EncapsulateSharedSecret` / `DecapsulateSharedSecret`
- `address.go`
  - 地址生成：`base58check`、`hash160_hex`、`ethereum_hex`
- `keystore.go`
  - 私钥加密解密（PBKDF2 + AES-GCM）
- `utils.go`
  - `RandomBytes`、`HashData`、`HMACSHA256`
- `types.go`
  - 对外类型与算法常量定义
- `*_test.go`
  - 最小回归测试（含 `cgo` 和 `!cgo` 路径）

## 3. 支持能力一览

### 3.1 签名算法

经典算法：

- `bls`
- `ecdsa`
- `ec_schnorr`
- `eddsa`
- `eddsa_cosmos`
- `sm2`

后量子签名：

- `pq_aigis_sig`
- `pq_dilithium`
- `pq_ml_dsa`
- `pq_slh_dsa`

### 3.2 后量子 KEM 算法

- `pq_ml_kem_512`
- `pq_ml_kem_768`
- `pq_ml_kem_1024`
- `pq_aigis_enc_1`
- `pq_aigis_enc_2`
- `pq_aigis_enc_3`
- `pq_aigis_enc_4`

### 3.3 地址与工具能力

- 地址格式：
  - `base58check`
  - `hash160_hex`
  - `ethereum_hex`
- 哈希：
  - `sha256`
  - `sha512`
  - `keccak256`
  - `ripemd160`
  - `hash160`
- HMAC：
  - `HMAC-SHA256`
- keystore：
  - 私钥加密与解密

## 4. 平台与依赖说明（非常重要）

### 4.1 PQC 相关能力需要 cgo

后量子签名和 KEM 依赖 `pqcgo`，而 `pqcgo` 的真实实现是 cgo + C 静态库。

- `CGO_ENABLED=1`：可用真实 PQC 实现
- `CGO_ENABLED=0`：可编译，但 PQC 接口会返回明确错误（例如 `pqcgo requires cgo`）

### 4.2 KEM 当前平台边界

当前 KEM 在代码中已明确为：

- `windows + cgo`：已实现并有回归测试
- `非 windows + cgo`：会返回 `pqcgo kem is currently supported on windows cgo builds`

### 4.3 编译器要求

如果你要使用 PQC（签名或 KEM），请确保本机具备可用 C 编译器（例如 Windows 下的 `gcc`）。

### 4.4 快速启动（从 clone 到可调用）

下面以 Windows + PowerShell 为例，给出最短启动路径。

1. 克隆项目并进入 `crypto` 模块：

```powershell
git clone https://github.com/19231224lhr/CryptoArea.git
cd CryptoArea/crypto
```

2. 验证基础能力（不依赖 cgo）：

```powershell
$env:CGO_ENABLED="0"
go test ./walletcrypto/...
```

3. 验证 PQC 能力（需要 cgo + gcc）：

```powershell
$env:CGO_ENABLED="1"
go test ./walletcrypto/...
```

4. 在你的业务代码中导入并调用：

```go
import "blockchain-crypto/walletcrypto"
```

如果你希望单独验证底层 `pqcgo`，可在仓库根目录执行：

```powershell
cd ../pqcgo
$env:CGO_ENABLED="1"
go test ./...
```

## 5. 在其他项目中导入

## 5.1 包导入路径

当前 `crypto` 模块的 `go.mod` 中模块名是：

`module blockchain-crypto`

所以在代码里导入：

```go
import "blockchain-crypto/walletcrypto"
```

## 5.2 本地仓库接入示例

如果你的钱包项目和本仓库在同一开发机本地，可用 `replace` 方式接入：

```go
require blockchain-crypto v0.0.0
replace blockchain-crypto => ../crypto-suites/crypto
```

如果你需要 PQC 功能，请确保 `blockchain-crypto` 模块内的 `pqcgo` 依赖仍正确指向（当前仓库已在 `crypto/go.mod` 配置本地 replace）。

## 6. API 速查与用途说明

### 6.1 密钥生成（签名）

```go
func GenerateKeyPair(algorithm string) (*KeyPair, error)
func GenerateKeyPairWithSeed(algorithm string, seed []byte) (*KeyPair, error)
```

用途：

- 为账户生成签名私钥/公钥
- 支持经典算法和后量子签名算法

### 6.2 签名与验签

```go
func SignMessage(algorithm string, privateKey []byte, message []byte) ([]byte, error)
func VerifyMessage(algorithm string, publicKey []byte, message []byte, signature []byte) (bool, error)
```

用途：

- 交易签名
- 交易验签/广播前本地验证

### 6.3 后量子 KEM

```go
func GenerateKEMKeyPair(algorithm string) (*KeyPair, error)
func EncapsulateSharedSecret(algorithm string, publicKey []byte) (ciphertext []byte, sharedSecret []byte, err error)
func DecapsulateSharedSecret(algorithm string, privateKey []byte, ciphertext []byte) (sharedSecret []byte, err error)
```

用途：

- 双方协商共享密钥（后续可用于会话加密、点对点安全通信）
- 注意：这不是交易签名，KEM 是“密钥交换”能力

### 6.4 地址生成

```go
func GenerateAddress(publicKey []byte, opts *AddressOptions) (string, error)
```

用途：

- 从公钥派生地址字符串（支持多种编码格式）

### 6.5 私钥加密存储

```go
func EncryptPrivateKey(privateKey []byte, passphrase []byte) ([]byte, error)
func DecryptPrivateKey(payload []byte, passphrase []byte) ([]byte, error)
```

用途：

- 将私钥加密后落盘（keystore）
- 钱包解锁时解密恢复私钥

### 6.6 工具函数

```go
func RandomBytes(length int) ([]byte, error)
func HashData(algorithm string, data []byte) ([]byte, error)
func HMACSHA256(key []byte, data []byte) []byte
```

用途：

- 随机种子、摘要、消息认证等基础密码场景

## 7. 快速调用示例

### 7.1 交易签名（后量子）

```go
package main

import (
	"fmt"
	"blockchain-crypto/walletcrypto"
)

func main() {
	kp, err := walletcrypto.GenerateKeyPair(walletcrypto.AlgPQMLDSA)
	if err != nil {
		panic(err)
	}

	msg := []byte("tx-bytes")
	sig, err := walletcrypto.SignMessage(walletcrypto.AlgPQMLDSA, kp.PrivateKey, msg)
	if err != nil {
		panic(err)
	}

	ok, err := walletcrypto.VerifyMessage(walletcrypto.AlgPQMLDSA, kp.PublicKey, msg, sig)
	if err != nil {
		panic(err)
	}
	fmt.Println("verify:", ok)
}
```

### 7.2 KEM 共享密钥协商

```go
package main

import (
	"bytes"
	"fmt"
	"blockchain-crypto/walletcrypto"
)

func main() {
	alice, _ := walletcrypto.GenerateKEMKeyPair(walletcrypto.AlgPQMLKEM768)
	bob, _ := walletcrypto.GenerateKEMKeyPair(walletcrypto.AlgPQMLKEM768)

	// Bob 使用 Alice 公钥封装共享密钥
	ct, ssBob, _ := walletcrypto.EncapsulateSharedSecret(walletcrypto.AlgPQMLKEM768, alice.PublicKey)
	// Alice 使用自己的私钥解封装
	ssAlice, _ := walletcrypto.DecapsulateSharedSecret(walletcrypto.AlgPQMLKEM768, alice.PrivateKey, ct)

	fmt.Println("same shared secret:", bytes.Equal(ssAlice, ssBob))
	_ = bob
}
```

### 7.3 地址与 keystore

```go
package main

import (
	"fmt"
	"blockchain-crypto/walletcrypto"
)

func main() {
	kp, _ := walletcrypto.GenerateKeyPair(walletcrypto.AlgECDSA)

	addr, _ := walletcrypto.GenerateAddress(kp.PublicKey, &walletcrypto.AddressOptions{
		Format:  walletcrypto.AddressFormatBase58Check,
		Version: 0x00,
	})
	fmt.Println("address:", addr)

	enc, _ := walletcrypto.EncryptPrivateKey(kp.PrivateKey, []byte("pass"))
	dec, _ := walletcrypto.DecryptPrivateKey(enc, []byte("pass"))
	fmt.Println("private key restored:", len(dec) > 0)
}
```

## 8. 典型钱包集成流程建议

账户创建流程：

1. `GenerateKeyPair(...)` 生成签名密钥对
2. `GenerateAddress(...)` 生成地址并入库
3. `EncryptPrivateKey(...)` 加密私钥后持久化

发送交易流程：

1. 使用口令调用 `DecryptPrivateKey(...)` 取出私钥
2. 组装交易消息
3. `SignMessage(...)` 生成签名
4. 广播前可先 `VerifyMessage(...)` 做本地校验

点对点安全通信（可选）：

1. 双方持有 KEM 公私钥对
2. 一方 `EncapsulateSharedSecret(...)`
3. 另一方 `DecapsulateSharedSecret(...)`
4. 双方得到同一共享密钥，供后续会话加密使用

## 9. 测试与验证

建议最小验证命令：

```bash
# 无 cgo 路径（确保降级行为正确）
CGO_ENABLED=0 go test ./walletcrypto/...

# 有 cgo 路径（验证 PQC 真正可用）
CGO_ENABLED=1 go test ./walletcrypto/...
```

对于 `pqcgo` 本身，也建议同步执行：

```bash
CGO_ENABLED=0 go test ./...
CGO_ENABLED=1 go test ./...
```

## 10. 当前边界与注意事项

- 本库重点提供“密码能力”，不是完整钱包协议实现（UTXO/账户模型、交易编码、脚本系统等仍由上层实现）。
- 地址生成是通用密码地址派生，不等同于某条链的全量地址规范实现。
- KEM 目前是 Windows cgo 路径可用，跨平台能力后续可继续扩展。
- 所有接口已按防御式校验处理非法输入，返回 `error`，避免 panic。
