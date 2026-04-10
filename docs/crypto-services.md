# CryptoArea 密码服务目录

本文整理 `CryptoArea` 当前对外可提供的主要密码服务，便于外部团队快速判断该仓库能否覆盖自己的接入需求。

## 1. 模块分层

| 模块 | 路径 | 角色 |
| --- | --- | --- |
| 主密码模块 | `github.com/19231224lhr/CryptoArea/crypto` | 对外推荐接入入口 |
| PQ 底层模块 | `github.com/19231224lhr/CryptoArea/pqcgo` | PQ 签名 / KEM 的底层封装 |
| WASM 模块 | `github.com/19231224lhr/CryptoArea/wasm/crypto` | wasm 侧包装与兼容层 |

## 2. walletcrypto 提供的服务

| 类别 | API | 说明 |
| --- | --- | --- |
| 密钥生成 | `GenerateKeyPair` | 支持经典签名与 PQ 签名 |
| 确定性密钥生成 | `GenerateKeyPairWithSeed` | 支持基于 seed 派生 |
| 签名 | `SignMessage` | 统一签名入口 |
| 验签 | `VerifyMessage` | 统一验签入口 |
| 地址生成 | `GenerateAddress` | 支持 Base58Check / Hash160 Hex / Keccak-last20 Hex |
| KEM 密钥生成 | `GenerateKEMKeyPair` | PQ KEM |
| KEM 封装 | `EncapsulateSharedSecret` | PQ KEM |
| KEM 解封装 | `DecapsulateSharedSecret` | PQ KEM |
| 私钥加密 | `EncryptPrivateKey` | keystore 场景 |
| 私钥解密 | `DecryptPrivateKey` | keystore 场景 |
| 随机数 | `RandomBytes` | 钱包与协议工具 |
| 哈希 | `HashData` | `sha256` / `sha512` / `keccak256` / `ripemd160` / `hash160` |
| HMAC | `HMACSHA256` | 常用消息认证 |
| Seed-chain 初始化 | `NewSeedChain` / `NewSeedChainFromSeed` | 哈希链一次一钥 |
| Seed-chain 恢复 | `RecoverSeedChain` | 基于 root seed 和 step 恢复 |
| Seed-chain 当前锚点 | `(*SeedChain).CurrentAnchor` | 获取当前 anchor |
| Seed-chain 当前密钥 | `(*SeedChain).DeriveCurrentKeyPair` | 获取当前步的确定性密钥 |
| Seed-chain 消费 | `(*SeedChain).ConsumeSeed` | 消费当前步并返回下一锚点 |

## 2.1 其他新增基础包

| 包 | 说明 |
| --- | --- |
| `crypto/evm` | `personal_sign` 哈希、恢复地址、校验地址、`bytes32` 编码 |
| `crypto/encoding/canonical` | 稳定 JSON 规范化与排除字段后的规范化 |
| `crypto/signature/secp256k1` | 显式 secp256k1 密钥、公钥、DER/可恢复签名辅助 |
| `crypto/symmetric` | AES-GCM / AES-OFB 与 OFB 文件流处理 |
| `crypto/compat/legacy` | 显式 legacy hash / 拼接兼容辅助 |
| `crypto/protocol/tmps` | TMPS bundle / proof input / challenge / verify 服务接口 |
| `crypto/protocol/tmps/codec/legacyv1` | BN254 / 标量 / proof input 的稳定兼容编码与服务实现 |
| `crypto/protocol/pre` | 通用 trusted-proxy 重加密封装，基于 secp256k1 ECIES 与 AES-GCM，并提供稳定编码与哈希服务 |
| `crypto/protocol/post` | strict / legacycompat profile 的 challenge/response transcript、稳定编码与验证服务 |

## 3. 当前支持的签名算法

### 3.1 经典签名

| 算法标识 | 说明 |
| --- | --- |
| `bls` | BLS 签名 |
| `ecdsa` | ECDSA（当前实现实际为 secp256k1） |
| `ec_schnorr` | EC Schnorr |
| `eddsa` | EdDSA |
| `eddsa_cosmos` | Cosmos 兼容 EdDSA |
| `sm2` | 国密 SM2 |

### 3.2 后量子签名

| 算法标识 | 说明 |
| --- | --- |
| `pq_aigis_sig` | AIGIS-SIG |
| `pq_dilithium` | Dilithium |
| `pq_ml_dsa` | ML-DSA |
| `pq_slh_dsa` | SLH-DSA |

## 4. 当前支持的 KEM 算法

| 算法标识 | 说明 |
| --- | --- |
| `pq_ml_kem_512` | ML-KEM-512 |
| `pq_ml_kem_768` | ML-KEM-768 |
| `pq_ml_kem_1024` | ML-KEM-1024 |
| `pq_aigis_enc_1` | AIGIS-ENC-1 |
| `pq_aigis_enc_2` | AIGIS-ENC-2 |
| `pq_aigis_enc_3` | AIGIS-ENC-3 |
| `pq_aigis_enc_4` | AIGIS-ENC-4 |

## 5. CGO 依赖边界

| 能力 | `CGO_ENABLED=0` | `CGO_ENABLED=1` |
| --- | --- | --- |
| 经典签名 | 可用 | 可用 |
| 地址生成 | 可用 | 可用 |
| keystore | 可用 | 可用 |
| 哈希/HMAC | 可用 | 可用 |
| 经典 seed-chain | 可用 | 可用 |
| PQ 签名 | 返回明确错误 | 可用 |
| PQ KEM | 返回明确错误 | 可用 |

## 5.1 语义提醒

- `walletcrypto.SignMessage("ecdsa", ...)` 是库内的通用 secp256k1 签名入口，不等价于 EVM `personal_sign`
- 若需要以太坊兼容地址恢复和校验，请使用 `crypto/evm`
- 若需要稳定 JSON 规范化，请使用 `crypto/encoding/canonical`

## 6. 推荐使用顺序

1. 先读 [external-usage-guide.md](./external-usage-guide.md)
2. 再看 [release-validation.md](./release-validation.md)
3. 最后跑 `crypto/examples/walletcrypto-seedchain-demo`
