# CryptoArea 外部使用指南

本文面向希望将 `CryptoArea` 作为底层密码库接入的钱包、账户系统或交易系统。

## 1. 仓库角色

`CryptoArea` 目前由两个核心 Go 模块组成：

| 模块 | 路径 | 作用 |
| --- | --- | --- |
| `github.com/19231224lhr/CryptoArea/crypto` | `./crypto` | 对外推荐主入口，提供经典签名、PQ 签名、KEM、地址、keystore、哈希工具、seed-chain |
| `github.com/19231224lhr/CryptoArea/pqcgo` | `./pqcgo` | 底层 PQ 封装，通常不建议业务代码直接耦合 |

对外项目默认应优先接：

```go
import "github.com/19231224lhr/CryptoArea/crypto/walletcrypto"
```

## 2. 当前可直接使用的能力

| 能力类别 | 主要 API |
| --- | --- |
| 密钥生成 | `GenerateKeyPair`、`GenerateKeyPairWithSeed` |
| 签名/验签 | `SignMessage`、`VerifyMessage` |
| 地址生成 | `GenerateAddress` |
| PQ KEM | `GenerateKEMKeyPair`、`EncapsulateSharedSecret`、`DecapsulateSharedSecret` |
| 私钥加密存储 | `EncryptPrivateKey`、`DecryptPrivateKey` |
| 工具函数 | `RandomBytes`、`HashData`、`HMACSHA256` |
| Seed-chain | `NewSeedChain`、`NewSeedChainFromSeed`、`RecoverSeedChain`、`(*SeedChain).ConsumeSeed` |

## 3. 支持的签名算法

### 3.1 经典签名

- `bls`
- `ecdsa`
- `ec_schnorr`
- `eddsa`
- `eddsa_cosmos`
- `sm2`

### 3.2 后量子签名

- `pq_aigis_sig`
- `pq_dilithium`
- `pq_ml_dsa`
- `pq_slh_dsa`

## 4. Seed-chain 适合什么场景

`walletcrypto.SeedChain` 适合这类需求：

- 地址保持稳定，但每笔交易使用不同的确定性签名密钥
- 需要“哈希链回退式”的一次一钥流程
- 需要同时兼容经典算法和 PQ 算法的确定性派生模型

默认流程是：

1. 用 `seed0` 构建完整哈希链
2. 从链尾开始消费 `seed[N]`
3. 每次消费时用当前 seed 派生一对确定性密钥
4. 计算下一步的 `anchor`，供后续状态锁定或协议校验使用

## 5. 最小接入示例

### 5.1 经典签名 + Seed-chain

```go
package main

import (
	"fmt"
	"github.com/19231224lhr/CryptoArea/crypto/walletcrypto"
)

func main() {
	sc, err := walletcrypto.NewSeedChain(walletcrypto.AlgECDSA, 4)
	if err != nil {
		panic(err)
	}

	seed, kp, step, nextAnchor, err := sc.ConsumeSeed()
	if err != nil {
		panic(err)
	}

	msg := []byte("walletcrypto-demo")
	sig, err := walletcrypto.SignMessage(walletcrypto.AlgECDSA, kp.PrivateKey, msg)
	if err != nil {
		panic(err)
	}
	ok, err := walletcrypto.VerifyMessage(walletcrypto.AlgECDSA, kp.PublicKey, msg, sig)
	if err != nil {
		panic(err)
	}

	fmt.Println("step:", step)
	fmt.Println("seed bytes:", len(seed))
	fmt.Println("next anchor bytes:", len(nextAnchor))
	fmt.Println("verify:", ok)
}
```

仓库内可直接运行：

```powershell
cd crypto
go run ./examples/walletcrypto-seedchain-demo
```

### 5.2 切到 PQ 签名

若运行环境已启用 `cgo` 并可正确调用 `pqcgo`，只需要把算法替换为：

```go
walletcrypto.AlgPQMLDSA
```

## 6. 本地联调时的 replace 建议

如果你在本地直接联调 `CryptoArea`，建议同时替换两个模块：

```go
replace github.com/19231224lhr/CryptoArea/crypto => /path/to/CryptoArea/crypto
replace github.com/19231224lhr/CryptoArea/pqcgo => /path/to/CryptoArea/pqcgo
```

这样可以保证：

- 你改动 `crypto/` 后，消费者立刻看到最新 `walletcrypto`
- 你改动 `pqcgo/` 后，消费者不会误拉远端旧版本

## 7. CGO 说明

- `CGO_ENABLED=0`
  - 经典算法、地址、hash、keystore、经典 seed-chain 流程可正常使用
  - PQ 接口会返回明确错误

- `CGO_ENABLED=1`
  - 可启用真实 PQ 签名 / KEM
  - 需要本机具备可用的 C 编译工具链

## 8. 推荐阅读顺序

1. [README.md](../README.md)
2. [crypto/README.MD](../crypto/README.MD)
3. [crypto/examples/walletcrypto-seedchain-demo/main.go](../crypto/examples/walletcrypto-seedchain-demo/main.go)
4. [crypto/walletcrypto/tx_flow_cgo_test.go](../crypto/walletcrypto/tx_flow_cgo_test.go)

