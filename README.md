# CryptoArea

`CryptoArea` 是一个面向钱包、账户系统和交易系统的底层密码库仓库，提供经典密码与后量子密码两套能力。

它的目标不是让业务项目自己去拼装底层算法，而是给上层工程提供一个清晰、稳定、可直接接入的密码能力入口。

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
| 地址生成 | 支持 Base58Check、Hash160 Hex、Ethereum Hex |
| Seed-chain | 支持哈希链一次一钥流程与确定性派生 |
| PQ KEM | 支持后量子密钥封装 / 解封装 |
| keystore | 支持私钥加密存储 |
| 哈希与工具函数 | 提供哈希、HMAC、随机数等通用工具 |

### 支持的签名算法

经典签名：

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

如需完整的 API 和能力边界，请看 [docs/crypto-services.md](./docs/crypto-services.md)。

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
