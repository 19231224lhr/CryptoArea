# PoST

`post` 提供一个通用的、版本化的 challenge/response transcript 服务。

当前 profile：

- `post-strict-v1`
  - `SHA-256`
  - `HMAC-SHA256`
- `post-legacycompat-v1`
  - `SHA-224`
  - `SHA256(key || data)` 兼容模式

当前能力：

- `GenerateChallenge`
- `Prove`
- `Verify`
- challenge / proof / material 的稳定编码
- challenge / proof 的稳定 hash

这个包适合沉淀“可复用的证明 transcript 规则”，不适合直接承载某个业务项目的全部 PoST 字段。

最小使用方式：

```go
service := post.MustNewService(post.WithProfile(post.ProfileLegacyCompatV1))
challenge, err := service.GenerateChallenge(material)
proof, err := service.Prove(proofMaterial)
result, err := service.Verify(verificationInput)
```

参考：

- 示例测试：`examples_test.go`
- 稳定向量：`testdata/reference_v1_golden.json`
