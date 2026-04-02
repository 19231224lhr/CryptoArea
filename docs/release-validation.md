# CryptoArea 发布前验证记录

日期：2026-04-02

本次验证面向 `CryptoArea` 作为底层密码库对外接入的发布前基线，重点覆盖：

- `github.com/19231224lhr/CryptoArea/crypto` 主模块
- `walletcrypto` 对外入口
- `pqcgo` 子模块
- `github.com/19231224lhr/CryptoArea/wasm/crypto` wasm 模块
- 外部消费者本地接入烟测

## 1. 默认环境验证

工作目录：`C:\Users\18360\Desktop\Code\CryptoArea\crypto`

执行：

```powershell
go test ./...
go run ./examples/walletcrypto-seedchain-demo
```

结果：

- `go test ./...` 通过
- seed-chain 示例通过，输出正常

## 1.1 WASM 模块默认验证

工作目录：`C:\Users\18360\Desktop\Code\CryptoArea\wasm\crypto`

执行：

```powershell
go test ./...
```

结果：

- `wasm/crypto` 模块测试通过

## 2. CGO + PQ 路径验证

环境：

```powershell
$env:PATH='C:\mingw64\bin;' + $env:PATH
$env:CGO_ENABLED='1'
$env:CC='C:\mingw64\bin\gcc.exe'
$env:CXX='C:\mingw64\bin\g++.exe'
```

执行：

```powershell
go test -count=1 ./walletcrypto/...
go test -race -count=1 ./walletcrypto/...
go vet ./walletcrypto/...
```

结果：

- `walletcrypto` 的 cgo 测试通过
- `walletcrypto` 的 race 测试通过
- `walletcrypto` 的 vet 通过

## 3. pqcgo 子模块验证

工作目录：`C:\Users\18360\Desktop\Code\CryptoArea\pqcgo`

执行：

```powershell
go test -count=1 ./...
```

结果：

- `pqcgo` 子模块测试通过

## 4. 外部消费者烟测

采用临时消费者模块进行本地接入验证。

### 4.1 经典算法 + Seed-chain

消费者 `go.mod` 关键配置：

```go
require (
  github.com/19231224lhr/CryptoArea/crypto v0.0.0
  github.com/19231224lhr/CryptoArea/pqcgo v0.0.0
)

replace github.com/19231224lhr/CryptoArea/crypto => C:/Users/18360/Desktop/Code/CryptoArea/crypto
replace github.com/19231224lhr/CryptoArea/pqcgo => C:/Users/18360/Desktop/Code/CryptoArea/pqcgo
```

执行：

```powershell
go mod tidy
go run .
```

结果：

- 输出：`external consumer ok true`

### 4.2 PQ 签名路径

在 `CGO_ENABLED=1` 环境下执行：

```powershell
go mod tidy
go run .
```

结果：

- 输出：`external pq consumer ok true`

## 5. 本轮发现并修复的发布阻塞项

### 5.1 pqcgo 模块路径不可对外解析

原问题：

- 原路径为 `teddycode/pqcgo`
- 对外消费者接入时会因模块路径不可公开解析而失败

修复：

- 改为 `github.com/19231224lhr/CryptoArea/pqcgo`
- 同步更新 `crypto/go.mod`、`walletcrypto` imports 与文档

### 5.2 walletcrypto 缺少正式 seed-chain API

原问题：

- 仓库里有 hash-chain 流程测试和设计文档
- 但缺少稳定、独立、可复用的 `SeedChain` 代码接口

修复：

- 新增 `walletcrypto.SeedChain`
- 补齐 `NewSeedChain` / `RecoverSeedChain` / `ConsumeSeed` / `CurrentAnchor` 等 API
- 增加默认测试、cgo 测试和示例程序

### 5.3 crypto 主模块路径不适合外部直接接入

原问题：

- 原模块路径为内部用的 `blockchain-crypto`
- 对外项目接入时不够标准，也不利于按公开仓库路径管理依赖

修复：

- 改为 `github.com/19231224lhr/CryptoArea/crypto`
- 同步更新仓库内 import、README、接入文档与外部烟测
- 同时将 `wasm/crypto` 调整为独立模块路径 `github.com/19231224lhr/CryptoArea/wasm/crypto`

## 6. 当前结论

可以认为 `CryptoArea` 已达到“对外接入前的基础发布可用水平”：

- 主模块可测试、可运行
- PQ 子模块可测试
- WASM 模块可测试
- 外部消费者本地烟测可通过
- `walletcrypto` 已具备更清晰的对外能力边界

## 7. 仍建议继续补强的项

- 多平台矩阵验证
- 多 Go 版本矩阵验证
- `walletcrypto` 包级 examples / 更多复杂示例
- 更正式的版本发布与 changelog 流程

