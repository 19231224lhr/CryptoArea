# PRE

`pre` 提供一个通用的、明确标注为 `trusted proxy` 的重加密封装。

当前方案：

- 数据内容：AES-GCM
- 数据密钥包装：secp256k1 ECIES
- 代理重加密：代理先解开委托给自己的数据密钥，再重新包装给新的接收方

这不是“代理永远看不到密钥”的数学型 PRE，而是一个更容易落地和互操作的通用协议层实现。

当前能力：

- `EncryptForRecipient` / `DecryptFromRecipient`
- `CreateDelegationToken` / `ReEncryptDataKey`
- payload / recipient / token / message 的稳定编码
- payload / recipient / token / message 的稳定 hash

最小使用方式：

```go
message, err := pre.EncryptForRecipient(plaintext, aad, recipientPublicKey)
token, err := pre.CreateDelegationToken(proxyPublicKey, delegateePublicKey, dataKey, metadata)
reEncrypted, err := pre.ReEncryptDataKey(token, proxyPrivateKey)
```

参考：

- 示例测试：`examples_test.go`
- 稳定向量：`testdata/reference_v1_golden.json`
