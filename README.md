# crypto-suites

`crypto-suites` 是一个面向钱包场景的密码能力库，整合了经典密码和后量子密码能力。

目标是给上层钱包/账户系统提供统一可调用的接口，覆盖：

- 私钥/公钥生成
- 签名与验签
- 地址生成
- 后量子 KEM（密钥封装/解封装）
- keystore（私钥加密存储）
- 常用哈希/HMAC/随机数工具

## 项目结构

- `crypto/`
  - 经典密码能力（签名、哈希等）
  - 对外推荐入口：`crypto/walletcrypto`
- `pqcgo/`
  - 后量子能力（签名 + KEM）的 Go 封装
  - 通过 cgo 调用 PQMagic C 库
- `wasm/`
  - wasm 相关封装与测试代码

## 推荐使用入口

钱包项目请优先通过 `crypto/walletcrypto` 使用，不建议业务层直接耦合底层多个模块。

导入路径：

```go
import "blockchain-crypto/walletcrypto"
```

## 支持算法

经典签名算法：

- `bls`
- `ecdsa`
- `ec_schnorr`
- `eddsa`
- `eddsa_cosmos`
- `sm2`

后量子签名算法：

- `pq_aigis_sig`
- `pq_dilithium`
- `pq_ml_dsa`
- `pq_slh_dsa`

后量子 KEM 算法：

- `pq_ml_kem_512`
- `pq_ml_kem_768`
- `pq_ml_kem_1024`
- `pq_aigis_enc_1`
- `pq_aigis_enc_2`
- `pq_aigis_enc_3`
- `pq_aigis_enc_4`

## 启动与验证（Windows + PowerShell）

1. 克隆仓库：

```powershell
git clone https://github.com/19231224lhr/CryptoArea.git
cd CryptoArea
```

2. 先验证无 cgo 路径（基础可编译性）：

```powershell
cd crypto
$env:CGO_ENABLED="0"
go test ./walletcrypto/...
```

3. 验证有 cgo 路径（后量子能力）：

```powershell
$env:CGO_ENABLED="1"
go test ./walletcrypto/...
```

4. 如需验证底层 `pqcgo`：

```powershell
cd ../pqcgo
$env:CGO_ENABLED="1"
go test ./...
```

## 对外核心接口（walletcrypto）

- 密钥生成
  - `GenerateKeyPair`
  - `GenerateKeyPairWithSeed`
- 签名验签
  - `SignMessage`
  - `VerifyMessage`
- KEM
  - `GenerateKEMKeyPair`
  - `EncapsulateSharedSecret`
  - `DecapsulateSharedSecret`
- 地址生成
  - `GenerateAddress`
- keystore
  - `EncryptPrivateKey`
  - `DecryptPrivateKey`
- 工具函数
  - `RandomBytes`
  - `HashData`
  - `HMACSHA256`

## 最小调用示例

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

## 重要说明

- PQC 相关能力依赖 `cgo`。
  - `CGO_ENABLED=1`：启用真实后量子实现
  - `CGO_ENABLED=0`：可编译，但 PQC 接口会返回明确错误
- 当前 KEM 的正式可用路径是 `windows + cgo`。
- `pqcgo/pqmagic/build-windows-kem/` 是本地构建中间目录，不是运行必需内容，已加入 `.gitignore`。
