# CryptoArea 外部使用指南

本文面向希望将 `CryptoArea` 作为底层密码库接入的钱包、账户系统或交易系统。

如果你是第一次进入本仓库，建议先看：

1. [本文](./external-usage-guide.md)
2. [密码服务目录](./crypto-services.md)
3. [文档导航](./README.md)

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

但请按能力边界选择入口：

- 钱包、PQ 签名、KEM、seed-chain：`walletcrypto`
- EVM 兼容 `personal_sign` / 恢复地址 / `bytes32` 编码：`crypto/evm`
- 结构化数据规范化：`crypto/encoding/canonical`

## 1.1 最小接入步骤

如果你是在一个新的 Go 项目里接入，推荐顺序如下：

```powershell
go mod init your-project
go get github.com/19231224lhr/CryptoArea/crypto@<tag-or-commit>
go mod tidy
```

然后在代码中导入：

```go
import "github.com/19231224lhr/CryptoArea/crypto/walletcrypto"
```

建议：

- 有正式 tag 时，优先使用 tag
- 还没发版但需要提前接入时，使用 commit hash
- 不建议把带 `/` 的分支名直接写进 `go get ...@branch`

## 1.2 下载源码后本地引用

如果你已经把 `CryptoArea` 下载到本地，不想先从远端拉模块，也可以直接引用本地源码。

这里有一个重要点：

- Go 代码中的 `import` 通常仍然保持模块路径
- 不建议把 `import` 直接写成 Windows 或 Linux 文件路径
- 正确做法是通过 `replace` 或 `go work` 把模块解析到本地目录

也就是说，代码里仍然建议写：

```go
import "github.com/19231224lhr/CryptoArea/crypto/walletcrypto"
```

### 方式 A：`go.mod` + `replace`

假设你本地有：

- `/path/to/CryptoArea/crypto`
- `/path/to/CryptoArea/pqcgo`

那么业务项目里可写：

```go
replace github.com/19231224lhr/CryptoArea/crypto => /path/to/CryptoArea/crypto
replace github.com/19231224lhr/CryptoArea/pqcgo => /path/to/CryptoArea/pqcgo
```

然后执行：

```powershell
go mod tidy
go run .
```

### 方式 B：使用 `go work`

如果你本地同时维护业务项目和 `CryptoArea`，可以使用 workspace：

```powershell
go work init
go work use /path/to/your-project
go work use /path/to/CryptoArea/crypto
go work use /path/to/CryptoArea/pqcgo
```

这种方式适合多仓库并行开发，同样不需要改源码里的 `import`。

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
| EVM 兼容 | `evm.PersonalSignHash`、`evm.RecoverAddressFromPersonalSign`、`evm.VerifyPersonalSignAddress`、`evm.Bytes32Hex` |
| Canonical JSON | `canonical.Canonicalize`、`canonical.CanonicalizeExcluding` |
| TMPS 编码兼容层 | `protocol/tmps/codec/legacyv1.MarshalProofInput`、`UnmarshalProofInput` |
| TMPS 服务骨架 | `GenerateChallenge`、`ProofHash`、`PublicKeyHash`、`ChallengeHash`、`VerifyEnvelope` |
| PRE 参考实现 | `protocol/pre.EncryptForRecipient`、`CreateDelegationToken`、`ReEncryptDataKey` |
| PRE 编码与哈希 | `MarshalPayload`、`MarshalDelegationToken`、`EncryptedMessageHash` |
| PoST 服务层 | `GenerateChallenge`、`Prove`、`Verify`、`ChallengeHash`、`ProofHash` |

## 3. 支持的签名算法

### 3.1 经典签名

- `bls`
- `ecdsa`（当前实现实际为 `secp256k1`）
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

## 5.3 EVM / 结构化数据场景

如果你的业务场景需要：

- `personal_sign`
- 从签名恢复地址
- `bytes32` 十六进制编码
- 结构化 JSON 规范化后再哈希 / 签名

请不要直接把这些行为压到 `walletcrypto` 上，而应分别使用：

```go
import "github.com/19231224lhr/CryptoArea/crypto/evm"
import "github.com/19231224lhr/CryptoArea/crypto/encoding/canonical"
```

说明：

- `walletcrypto.SignMessage(AlgECDSA, ...)` 是库内的通用 secp256k1 签名入口
- 它不是 EVM `personal_sign` 语义，也不负责恢复地址
- `walletcrypto.GenerateAddress(..., AddressFormatEthereumHex)` 当前是 Keccak-last20 风格地址派生，不应直接当作完整 EVM 兼容层

## 6. 本地联调时的 replace 建议

如果你在本地直接联调 `CryptoArea`，建议同时替换两个模块：

```go
replace github.com/19231224lhr/CryptoArea/crypto => /path/to/CryptoArea/crypto
replace github.com/19231224lhr/CryptoArea/pqcgo => /path/to/CryptoArea/pqcgo
```

这样可以保证：

- 你改动 `crypto/` 后，消费者立刻看到最新 `walletcrypto`
- 你改动 `pqcgo/` 后，消费者不会误拉远端旧版本

如果你只是普通外部接入，而不是本地联调，请不要默认加 `replace`，直接使用远端模块即可。

## 7. CGO 说明

- `CGO_ENABLED=0`
  - 经典算法、地址、hash、keystore、经典 seed-chain 流程可正常使用
  - PQ 接口会返回明确错误

- `CGO_ENABLED=1`
  - 可启用真实 PQ 签名 / KEM
  - 需要本机具备可用的 C 编译工具链

## 8. 真实接入时的常见提醒

- `go get` 之后建议补一次 `go mod tidy`
- 仅导入 `walletcrypto.AlgECDSA` 这类经典能力时，不需要启用 `cgo`
- 需要 PQ 签名 / KEM 时，再准备 `CGO_ENABLED=1` 环境
- 若当前版本尚未打 tag，推荐用 commit hash 固定依赖版本

## 9. 推荐阅读顺序

1. [README.md](../README.md)
2. [crypto/README.MD](../crypto/README.MD)
3. [crypto/examples/walletcrypto-seedchain-demo/main.go](../crypto/examples/walletcrypto-seedchain-demo/main.go)
4. [crypto/walletcrypto/tx_flow_cgo_test.go](../crypto/walletcrypto/tx_flow_cgo_test.go)

