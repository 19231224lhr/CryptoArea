# TMPS

`tmps` 提供一组通用的数据结构和服务接口，用于承载基于 BN254 配对曲线的证明协议输入输出。

当前能力：

- `Bundle` / `ProofInput` / `ChallengeMaterial` / `VerificationInput`
- `legacyv1` 稳定编码
- challenge 生成
- `proofHash` / `pkHash` / `challengeHash`
- pairing verify plan

当前还没有实现某个外部项目专属的完整 `Setup / Prove / Verify` 业务协议；库里沉淀的是：

- 可复用的数据模型
- 可复用的编码和 hash helper
- 可复用的 pairing 校验骨架

最小使用方式：

```go
service := legacyv1.MustNewService()
challenge, err := service.GenerateChallenge(material)
proofHash, err := service.ProofHash(input)
result, err := service.VerifyWithPlan(input, options)
```

参考：

- 示例测试：`examples_test.go`
- 稳定向量：`testdata/legacyv1_golden.json`
