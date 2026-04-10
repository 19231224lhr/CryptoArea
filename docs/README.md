# CryptoArea 文档导航

本文档用于帮助不同角色快速找到应该阅读的内容。

## 1. 外部工程师接入

如果你是第一次接入 `CryptoArea`，建议按下面顺序阅读：

1. [外部使用指南](./external-usage-guide.md)
2. [密码服务目录](./crypto-services.md)
3. [../crypto/README.MD](../crypto/README.MD)
4. [../crypto/examples/walletcrypto-seedchain-demo/main.go](../crypto/examples/walletcrypto-seedchain-demo/main.go)
5. [../crypto/protocol/README.md](../crypto/protocol/README.md)

其中：

- [外部使用指南](./external-usage-guide.md)
  - 适合“我要怎么接”
  - 重点说明推荐入口、远端接入方式、本地联调方式、CGO 边界
- [密码服务目录](./crypto-services.md)
  - 适合“这个库到底提供什么”
  - 用表格汇总支持的算法、API、模块和能力边界
- [../crypto/protocol/README.md](../crypto/protocol/README.md)
  - 适合“新增协议层现在具体有哪些包”
  - 重点说明 `tmps` / `pre` / `post` 的边界和示例入口

## 2. 内部发布与验收

如果你是在做发布、交付或验收，重点看：

1. [发布前验证记录](./release-validation.md)
2. [发布清单](./release-checklist.md)

其中：

- [发布前验证记录](./release-validation.md)
  - 说明这次版本实际做了哪些测试、在什么环境下通过
- [发布清单](./release-checklist.md)
  - 用于发布前最后逐项确认

## 3. 设计与历史参考

下面两份更适合作为背景资料，不建议外部接入者把它们当成第一入口：

1. [CryptoArea 密码库使用说明文档](./crypto-library-guide.md)
2. [PQC-UTXO-Simulator 设计文档](./pqc-utxo-simulator-design.md)

它们的作用分别是：

- [crypto-library-guide.md](./crypto-library-guide.md)
  - 更完整、更偏说明书式的总览
  - 适合内部统一认知、培训或写方案时引用
- [pqc-utxo-simulator-design.md](./pqc-utxo-simulator-design.md)
  - 偏历史背景和方案设计
  - 适合了解 `CryptoArea` 与 `PQC-UTXO-Simulator` 的关系

## 4. 一句话建议

- 外部工程师：先看 [external-usage-guide.md](./external-usage-guide.md)
- 想知道支持什么：再看 [crypto-services.md](./crypto-services.md)
- 想确认发布质量：看 [release-validation.md](./release-validation.md)
