# CryptoArea

`CryptoArea` 是一个面向钱包、账户系统和交易系统的底层密码库仓库，提供经典密码与后量子密码两套能力。

它的目标不是让业务项目自己去拼装底层算法，而是给上层工程提供一个清晰、稳定、可直接接入的密码能力入口。

当前代码里 `walletcrypto.AlgECDSA` 对应的实际实现是 **secp256k1**，不是 P-256。
如果你需要 EVM / `personal_sign` / 地址恢复这类以太坊兼容能力，应优先使用新增的：

```go
import "github.com/19231224lhr/CryptoArea/crypto/evm"
import "github.com/19231224lhr/CryptoArea/crypto/encoding/canonical"
```

## 我该看什么

如果你是第一次接入这个仓库，建议按下面顺序阅读：

| 你想解决的问题 | 先看什么 |
| --- | --- |
| 我该怎么接入这个库 | [docs/external-usage-guide.md](./docs/external-usage-guide.md) |
| 这个库到底提供哪些密码服务 | [docs/crypto-services.md](./docs/crypto-services.md) |
| 我想先看一个最小可运行示例 | [crypto/examples/walletcrypto-seedchain-demo/main.go](./crypto/examples/walletcrypto-seedchain-demo/main.go) |
| 我想确认发布前是否已经验证过 | [docs/release-validation.md](./docs/release-validation.md) |
| 我想了解设计背景和历史方案 | [docs/crypto-library-guide.md](./docs/crypto-library-guide.md) |

外部工程师默认不需要先看 `release-*` 文档，也不建议把设计背景文档作为第一入口。

## 仓库定位

`CryptoArea` 当前主要包含 3 个模块：

| 模块 | 路径 | 角色 |
| --- | --- | --- |
| 主密码模块 | `github.com/19231224lhr/CryptoArea/crypto` | 对外推荐主入口 |
| PQ 底层模块 | `github.com/19231224lhr/CryptoArea/pqcgo` | 后量子签名 / KEM 的底层封装 |
| WASM 模块 | `github.com/19231224lhr/CryptoArea/wasm/crypto` | wasm 场景下的包装与兼容层 |

对于大多数钱包或账户系统，推荐直接接：

```go
import "github.com/19231224lhr/CryptoArea/crypto/walletcrypto"
```

不建议业务代码一开始就直接耦合 `pqcgo`。

如果你的接入场景是：

- 钱包、seed-chain、PQ 签名 / KEM：优先接 `walletcrypto`
- `personal_sign`、恢复地址、EVM 兼容 keccak：优先接 `crypto/evm`
- 结构化 JSON 规范化与跨端一致哈希：优先接 `crypto/encoding/canonical`

## 外部工程师快速接入

如果你是在一个全新的 Go 项目里接入 `CryptoArea`，最小流程如下：

```powershell
go mod init your-project
go get github.com/19231224lhr/CryptoArea/crypto@<tag-or-commit>
go mod tidy
```

然后在代码里导入：

```go
import "github.com/19231224lhr/CryptoArea/crypto/walletcrypto"
```

说明：

- 已发布 tag 时，优先使用 tag
- 若还未发布正式版本，可临时使用 commit hash
- 不建议把带 `/` 的分支名直接写进 `go get ...@branch`，Go 的版本字符串规则对这类分支名不稳定

## 下载源码后本地引用

如果你不想先从远端拉模块，而是已经把 `CryptoArea` 仓库下载到了本地，也可以直接引用本地源码。

需要注意一个 Go 的规则：

- 代码里的 `import` 一般**仍然写模块路径**
- 本地引用通常不是把 `import` 改成磁盘路径
- 而是在 `go.mod` 里通过 `replace`，或者通过 `go work`，把模块解析到本地目录

也就是说，代码里仍然建议写：

```go
import "github.com/19231224lhr/CryptoArea/crypto/walletcrypto"
```

### 方式 1：使用 `replace`

假设你本地已经有：

- `C:/path/to/CryptoArea/crypto`
- `C:/path/to/CryptoArea/pqcgo`

你的业务项目 `go.mod` 可以这样写：

```go
replace github.com/19231224lhr/CryptoArea/crypto => C:/path/to/CryptoArea/crypto
replace github.com/19231224lhr/CryptoArea/pqcgo => C:/path/to/CryptoArea/pqcgo
```

然后执行：

```powershell
go mod tidy
go run .
```

### 方式 2：使用 `go work`

如果你本地同时维护业务项目和 `CryptoArea`，也可以用 workspace：

```powershell
go work init
go work use C:/path/to/your-project
go work use C:/path/to/CryptoArea/crypto
go work use C:/path/to/CryptoArea/pqcgo
```

这种方式同样不需要改业务代码里的 `import`。

## 当前提供的核心能力

| 能力类别 | 说明 |
| --- | --- |
| 密钥生成 | 支持经典签名与后量子签名密钥生成 |
| 签名与验签 | 统一的 `SignMessage` / `VerifyMessage` 入口 |
| 地址生成 | 支持 Base58Check、Hash160 Hex、Keccak-last20 Hex |
| Seed-chain | 支持哈希链一次一钥流程与确定性派生 |
| PQ KEM | 支持后量子密钥封装 / 解封装 |
| keystore | 支持私钥加密存储 |
| 哈希与工具函数 | 提供哈希、HMAC、随机数等通用工具 |
| EVM 兼容辅助 | 提供 `personal_sign` 哈希、恢复地址、校验地址、`bytes32` 编码 |
| Canonical JSON | 提供稳定 JSON 规范化与排除字段后的规范化 |
| 通用对称加密 | 提供 AES-GCM / AES-OFB 原语与 OFB 文件流处理 |
| 迁移兼容工具 | 提供 legacy hash/拼接规则的显式兼容入口 |
| TMPS 编码兼容层 | 提供 BN254 元素、标量与 proof input 的 legacyv1 稳定编码 |
| TMPS 服务骨架 | 提供 challenge 生成、proof/pk/challenge 哈希与 envelope 完整性校验 |
| PRE 参考实现 | 提供基于 secp256k1 ECIES + AES-GCM 的 trusted-proxy 重加密封装 |
| PRE 稳定编码层 | 提供 payload / token / recipient / message 的 canonical JSON 编码与哈希 |
| PoST 服务层 | 提供 strict / legacycompat profile 的 challenge、proof、verify 与稳定编码 |

### 支持的签名算法

经典签名：

- `bls`
- `ecdsa`（当前实现实际为 `secp256k1`）
- `ec_schnorr`
- `eddsa`
- `eddsa_cosmos`
- `sm2`

后量子签名：

- `pq_aigis_sig`
- `pq_dilithium`
- `pq_ml_dsa`
- `pq_slh_dsa`

如需完整的 API 和能力边界，请看 [docs/crypto-services.md](./docs/crypto-services.md)。

说明：

- `walletcrypto.SignMessage(ecdsa)` 是当前库内的通用 secp256k1 签名入口，不等价于以太坊 `personal_sign`
- 如果你需要 EVM 兼容消息哈希、恢复地址、校验地址，请使用 `crypto/evm`
- 如果你需要结构化文档签名前的稳定 JSON 规范化，请使用 `crypto/encoding/canonical`

## 设计规范参考：做成可替换的密码基座

如果其他项目要接入 `CryptoArea`，我们建议不要把某一种密码算法直接写死在业务逻辑里，而是把密码相关模块设计成**可替换、可扩展的底层基座**。

推荐思路是：

- 业务层只依赖统一接口，不直接依赖具体算法实现
- 在配置、交易结构、账户结构或密钥元数据中保留一个“算法类型字段”
- 根据该字段在运行时选择具体密码实现

可以用整数枚举，也可以用字符串枚举。  
如果项目已经有固定的协议字段，使用 `type=0/1/2...` 这种方式是完全可以的。

例如：

| `type` | 含义 | 建议对应算法 |
| --- | --- | --- |
| `0` | 经典默认签名 | `ecdsa` |
| `1` | 默认后量子签名 | `pq_ml_dsa` |
| `2` | 兼容型后量子签名 | `pq_dilithium` |
| `3` | 哈希基后量子签名 | `pq_slh_dsa` |

核心目标不是这个数字本身，而是：

- **上层协议稳定**
- **底层算法可替换**
- **新增算法时不需要重写业务流程**

推荐把以下能力都放到同一套可替换抽象下面：

- 密钥生成
- 签名
- 验签
- 地址生成
- Seed-chain 派生
- KEM

也就是说，上层最好只认这种统一入口：

```go
GenerateKeyPair(algType, ...)
SignMessage(algType, ...)
VerifyMessage(algType, ...)
GenerateAddress(algType, ...)
```

而不是在业务代码里到处分支调用不同算法包。

### 一个建议的接入模型

```go
type CryptoType int

const (
    CryptoTypeECDSA CryptoType = 0
    CryptoTypePQMLDSA CryptoType = 1
    CryptoTypePQDilithium CryptoType = 2
    CryptoTypePQSLHDSA CryptoType = 3
)
```

然后在你的账户、地址、交易输入、签名元数据里带上这个字段，由底层统一分发到具体实现。

### 这样做的好处

- 经典密码切到后量子密码时，业务层改动最小
- 一个系统里可以并存多种算法
- 可以逐步迁移，不需要一次性替换所有历史数据
- 更适合把 `CryptoArea` 当成长期可演进的密码底座

如果你只想先快速接入，仍然建议从默认入口开始：

```go
import "github.com/19231224lhr/CryptoArea/crypto/walletcrypto"
```

后续再把算法选择从“写死”逐步提升到“可配置 / 可协商 / 可迁移”。

## 文档分类

`docs/` 里的文档按用途可以这样理解：

### 1. 接入文档

- [docs/external-usage-guide.md](./docs/external-usage-guide.md)

适合外部工程师，重点回答“怎么接”“先看什么”“最小示例怎么跑”。

### 2. 能力目录

- [docs/crypto-services.md](./docs/crypto-services.md)

适合架构师、技术负责人、选型人员，重点回答“这个库到底提供什么”“支持哪些算法和服务”。

### 3. 发布与验收

- [docs/release-validation.md](./docs/release-validation.md)
- [docs/release-checklist.md](./docs/release-checklist.md)

适合维护者、交付方、验收方。外部接入者通常不需要把这两份作为第一阅读入口。

### 4. 设计与历史参考

- [docs/crypto-library-guide.md](./docs/crypto-library-guide.md)
- [docs/pqc-utxo-simulator-design.md](./docs/pqc-utxo-simulator-design.md)

这两份更偏背景、方案和历史关系说明：

- `crypto-library-guide.md` 更像完整说明书，适合内部培训、方案引用或深入了解。
- `pqc-utxo-simulator-design.md` 是背景设计文档，适合需要理解 `CryptoArea` 与相关上层项目关系的人。

## 最小上手路径

### 1. 先看推荐接入入口

```go
import "github.com/19231224lhr/CryptoArea/crypto/walletcrypto"
```

### 2. 拉取依赖

```powershell
go get github.com/19231224lhr/CryptoArea/crypto@<tag-or-commit>
go mod tidy
```

### 3. 运行最小示例

```powershell
cd crypto
go run ./examples/walletcrypto-seedchain-demo
```

### 4. 做一次基础验证

无 `cgo` 环境下先验证经典能力：

```powershell
cd crypto
$env:CGO_ENABLED="0"
go test ./walletcrypto/...
```

如需验证后量子能力，再切到启用 `cgo` 的环境。

## 推荐阅读顺序

如果你是第一次评估或接入 `CryptoArea`，建议顺序如下：

1. [docs/external-usage-guide.md](./docs/external-usage-guide.md)
2. [docs/crypto-services.md](./docs/crypto-services.md)
3. [crypto/README.MD](./crypto/README.MD)
4. [crypto/examples/walletcrypto-seedchain-demo/main.go](./crypto/examples/walletcrypto-seedchain-demo/main.go)

## 更多入口

- 文档导航：[docs/README.md](./docs/README.md)
- 主模块说明：[crypto/README.MD](./crypto/README.MD)
- 发布前验证记录：[docs/release-validation.md](./docs/release-validation.md)
- 发布清单：[docs/release-checklist.md](./docs/release-checklist.md)
