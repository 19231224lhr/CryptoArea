# CryptoArea 发布清单

以下清单面向正式发布 `CryptoArea` 前的最后确认。

## 1. 模块与路径

- [ ] `crypto/go.mod` 使用公开可解析的模块路径
- [ ] `pqcgo/go.mod` 使用公开可解析的模块路径
- [ ] `wasm/crypto/go.mod` 使用独立模块路径
- [ ] 文档中的 import / replace 示例与当前模块路径一致

## 2. 代码质量

- [ ] `go test ./...`（`crypto`）通过
- [ ] `go test ./...`（`pqcgo`）通过
- [ ] `go test ./...`（`wasm/crypto`）通过
- [ ] `go vet ./walletcrypto/...` 通过
- [ ] `go test -race ./walletcrypto/...` 通过

## 3. 示例与外部接入

- [ ] `go run ./examples/walletcrypto-seedchain-demo` 通过
- [ ] 外部消费者经典烟测通过
- [ ] 外部消费者 PQ 烟测通过

## 4. 文档

- [ ] 根 README 已链接外部使用指南
- [ ] `docs/external-usage-guide.md` 最新
- [ ] `docs/crypto-services.md` 最新
- [ ] `docs/release-validation.md` 最新

## 5. 发布备注

- [ ] 记录本次版本变更点
- [ ] 确认是否需要 tag
- [ ] 确认是否需要同步上层项目接入路径
