# CryptoArea 密码库使用说明文档

> 版本：v5.1 | 日期：2026-03-02
>
> v3.0 更新：ECDSA 作为默认签名算法、PQ 作为可选扩展；新增第五章 UTXO-Area 转账区完整集成方案

---

## 一、总体概述

`CryptoArea`（模块名 `crypto-suites`）是一个面向区块链钱包场景的统一密码能力库，整合了**经典密码**和**后量子密码（PQC）** 两套能力体系，为上层钱包/账户系统提供统一的调用接口。

### 1.1 核心能力

| 能力类别 | 说明 |
|---------|------|
| 密钥生成 | 支持经典（ECDSA 等）和后量子（ML-DSA 等）密钥对生成 |
| 确定性密钥派生 | 支持从 Seed 确定性生成密钥对（同一 Seed → 同一密钥对） |
| 签名与验签 | 支持全部经典和后量子签名算法 |
| 地址生成 | 公钥 → 地址（Base58Check / Hash160 / Ethereum 风格） |
| KEM 密钥封装 | 后量子密钥封装/解封装（协商对称密钥） |
| Keystore | 私钥加密存储（AES-256-GCM + PBKDF2） |
| 哈希工具 | SHA256、SHA512、Keccak256、RIPEMD160、Hash160 等 |
| 随机数 | 密码学安全随机数生成 |

### 1.2 项目结构

```
CryptoArea/
├── crypto/                    ← Go 模块 "github.com/19231224lhr/CryptoArea/crypto"
│   ├── hash/                  ← 哈希算法集合
│   │   ├── sha256/
│   │   ├── sha512/
│   │   ├── sha3/              ← Keccak256 等
│   │   ├── ripemd160/
│   │   ├── poseidon/
│   │   ├── scrypt/
│   │   └── blake2b/ blake2s/
│   ├── signature/             ← 经典签名算法集合
│   │   ├── bls/
│   │   ├── ecdsa/
│   │   ├── ec_schnorr/
│   │   ├── eddsa/
│   │   ├── eddsa_cosmos/
│   │   └── sm2/
│   ├── types/                 ← 曲线类型定义
│   └── walletcrypto/          ← ★ 推荐对外统一入口
│       ├── api.go             ← 密钥生成、签名、验签
│       ├── address.go         ← 地址生成
│       ├── kem.go             ← KEM 封装/解封装
│       ├── keystore.go        ← 私钥加密存储
│       ├── types.go           ← 类型定义和算法常量
│       └── utils.go           ← 哈希、随机数工具
├── pqcgo/                     ← Go 模块 "github.com/19231224lhr/CryptoArea/pqcgo"
│   ├── constants.go           ← PQC 签名算法参数常量
│   ├── kem_constants.go       ← PQC KEM 算法参数常量
│   ├── pqcsign.go             ← PQC 签名 cgo 封装（cgo 构建）
│   ├── pqcsign_nocgo.go       ← PQC 签名无 cgo 回退（返回错误）
│   ├── pqckem_windows.go      ← PQC KEM cgo 封装（Windows）
│   ├── pqckem_unsupported.go  ← PQC KEM 非 Windows 回退
│   ├── pqcsign_wrapper.c/.h   ← C 层签名包装器
│   ├── pqckem_wrapper*.c/.h   ← C 层 KEM 包装器
│   ├── wallet_api.go          ← pqcgo 层自有钱包 API
│   ├── wallet_address.go      ← pqcgo 层地址生成
│   ├── fips202.c/.h           ← SHAKE256 实现
│   ├── randombytes.c/.h       ← 随机数 C 实现
│   ├── libs/                  ← 预编译的 PQMagic 静态库
│   │   ├── include/           ← C 头文件
│   │   └── lib/win/ lib/linux/← 平台静态库 .a
│   └── pqmagic/               ← PQMagic C 库源码（可重编译）
└── wasm/                      ← WebAssembly 封装（经典签名）
```

### 1.3 模块依赖关系

```
业务层（钱包/区块链节点）
       │
       ▼
  walletcrypto        ← ★ 推荐唯一入口
       │
   ┌───┴───┐
   ▼       ▼
signature  pqcgo      ← 经典签名 / 后量子签名+KEM
   │       │
   ▼       ▼
  hash   PQMagic C库   ← 哈希实现 / 后量子 C 实现
```

`crypto/walletcrypto` 通过 Go `replace` 指令引用 `pqcgo`：

```go
// crypto/go.mod
replace github.com/19231224lhr/CryptoArea/pqcgo => ../pqcgo
```

---

## 二、支持算法清单

### 2.1 经典签名算法（纯 Go，不依赖 cgo）

| 算法常量名 | 算法 | 说明 |
|-----------|------|------|
| `ecdsa` | ECDSA P-256 | 最常用的经典签名 |
| `bls` | BLS12-381 | 可聚合的签名方案 |
| `ec_schnorr` | EC-Schnorr | Schnorr 签名变体 |
| `eddsa` | Ed25519 | 高性能签名 |
| `eddsa_cosmos` | Ed25519 (Cosmos) | Cosmos 生态变体 |
| `sm2` | 国密 SM2 | 国密标准 |

### 2.2 后量子签名算法（需要 cgo）

| 算法常量名 | scheme 编号 | 公钥 (字节) | 私钥 (字节) | 签名 (字节) | 底层算法 | 安全假设 |
|-----------|:-----------:|:-----------:|:-----------:|:-----------:|---------|---------|
| `pq_aigis_sig` | 0 | 1,568 | 3,888 | 3,046 | Aigis-Sig3 | 格基 (Lattice) |
| `pq_dilithium` | 1 | 1,952 | 4,000 | 3,293 | CRYSTALS-Dilithium3 | 格基 (Lattice) |
| `pq_ml_dsa` | 2 | 1,952 | 4,032 | 3,309 | ML-DSA-65 (FIPS 204) | 格基 (Lattice) |
| `pq_slh_dsa` | 3 | 48 | 96 | 35,664 | SLH-DSA-SHAKE-192f | 哈希基 (Hash) |

**推荐：默认优先使用 `pq_ml_dsa`（ML-DSA-65）**，它是 NIST 正式标准化的后量子签名算法。

### 2.3 后量子 KEM 算法（需要 cgo + Windows）

| 算法常量名 | scheme 编号 | 公钥 (字节) | 私钥 (字节) | 密文 (字节) | 共享密钥 (字节) |
|-----------|:-----------:|:-----------:|:-----------:|:-----------:|:--------------:|
| `pq_ml_kem_512` | 0 | 800 | 1,632 | 768 | 32 |
| `pq_ml_kem_768` | 1 | 1,184 | 2,400 | 1,088 | 32 |
| `pq_ml_kem_1024` | 2 | 1,568 | 3,168 | 1,568 | 32 |
| `pq_aigis_enc_1` | 3 | 672 | 1,568 | 736 | 32 |
| `pq_aigis_enc_2` | 4 | 896 | 2,208 | 992 | 32 |
| `pq_aigis_enc_3` | 5 | 992 | 2,304 | 1,056 | 32 |
| `pq_aigis_enc_4` | 6 | 1,440 | 3,168 | 1,568 | 32 |

### 2.4 平台兼容性

| 能力 | CGO_ENABLED=0 | CGO_ENABLED=1 (Windows) | CGO_ENABLED=1 (Linux) |
|------|:---:|:---:|:---:|
| 经典签名 | ✅ | ✅ | ✅ |
| 哈希/地址/Keystore | ✅ | ✅ | ✅ |
| PQC 签名 | ❌ | ✅ | ✅ |
| PQC KEM | ❌ | ✅ | ❌ |

---

## 三、核心 API 参考

所有 API 均通过 `walletcrypto` 包统一暴露。

### 3.1 密钥生成

```go
import "github.com/19231224lhr/CryptoArea/crypto/walletcrypto"

// 随机生成密钥对
kp, err := walletcrypto.GenerateKeyPair("pq_ml_dsa")
// kp.Algorithm  = "pq_ml_dsa"
// kp.PublicKey   → []byte (1952 bytes)
// kp.PrivateKey  → []byte (4032 bytes)

// 从 Seed 确定性生成密钥对（同一 algorithm + seed → 同一密钥对）
seed := []byte("my-deterministic-seed")
kp, err := walletcrypto.GenerateKeyPairWithSeed("pq_ml_dsa", seed)
```

**确定性派生原理**：Seed → SHAKE256 扩展为 72 字节内部种子 → 传给算法的 `keypair_internal` 函数。

### 3.2 签名与验签

```go
// 签名
sig, err := walletcrypto.SignMessage("pq_ml_dsa", kp.PrivateKey, message)

// 验签
ok, err := walletcrypto.VerifyMessage("pq_ml_dsa", kp.PublicKey, message, sig)
```

### 3.3 地址生成

```go
// Base58Check 地址（类似 BTC 风格）
addr, err := walletcrypto.GenerateAddress(kp.PublicKey, &walletcrypto.AddressOptions{
    Format:  walletcrypto.AddressFormatBase58Check,
    Version: 0x00,
})

// Hash160 Hex 地址
addr, err := walletcrypto.GenerateAddress(kp.PublicKey, &walletcrypto.AddressOptions{
    Format: walletcrypto.AddressFormatHash160Hex,
})

// 以太坊风格 Keccak256 地址
addr, err := walletcrypto.GenerateAddress(kp.PublicKey, &walletcrypto.AddressOptions{
    Format: walletcrypto.AddressFormatEthereumHex,
})
```

地址生成管线：`PublicKey → SHA256 → RIPEMD160 → [Version + Payload + Checksum] → Base58`

### 3.4 KEM 密钥封装

```go
// 生成 KEM 密钥对
kemKP, err := walletcrypto.GenerateKEMKeyPair("pq_ml_kem_768")

// 封装（发送方用对方公钥）
ciphertext, sharedSecret, err := walletcrypto.EncapsulateSharedSecret("pq_ml_kem_768", kemKP.PublicKey)

// 解封装（接收方用自己私钥）
sharedSecret2, err := walletcrypto.DecapsulateSharedSecret("pq_ml_kem_768", kemKP.PrivateKey, ciphertext)
// sharedSecret == sharedSecret2 (32 bytes)
```

### 3.5 Keystore 私钥加密存储

```go
// 加密（AES-256-GCM + PBKDF2, 100000 轮）
encrypted, err := walletcrypto.EncryptPrivateKey(kp.PrivateKey, []byte("password"))
// encrypted 格式: [Version(1B)][Salt(16B)][Nonce(12B)][Ciphertext+AuthTag]

// 解密
decrypted, err := walletcrypto.DecryptPrivateKey(encrypted, []byte("password"))
```

### 3.6 哈希与工具

```go
// 哈希
hash, err := walletcrypto.HashData("sha256", data)
hash, err := walletcrypto.HashData("keccak256", data)
hash, err := walletcrypto.HashData("hash160", data)  // SHA256 → RIPEMD160

// HMAC
mac := walletcrypto.HMACSHA256(key, data)

// 安全随机数
randomBytes, err := walletcrypto.RandomBytes(32)
```

---

## 四、Seed 链与一次一钥方案：核心设计

这是整个密码方案中最关键的设计部分。在我们的区块链系统中，我们采用 **"用 masterSeed 生成地址，用 Seed_N → Seed_1 逐笔签名"** 的方案，以实现前向安全与未来后量子防护。

> **算法选择说明（v3.0）：** 当前阶段，seed 链派生的签名密钥对使用 **ECDSA P-256**（与 UTXO-Area 现有系统一致）。后量子算法（ML-DSA-65 等）作为 **可选扩展**，通过配置切换即可启用，无需修改链上协议。本文中的 `SignAlgorithm` 参数默认为 `"ecdsa_p256"`，如启用后量子则替换为 `"pq_ml_dsa"`。

### 4.1 总体思路

```
┌───────────────────────────────────────────────────────────────┐
│                    一个地址的完整生命周期                        │
├───────────────────────────────────────────────────────────────┤
│                                                               │
│  masterSeed（主种子，永不暴露）                                  │
│    │                                                          │
│    ├── 用 masterSeed 确定性派生 → 公钥0 / 私钥0（ECDSA 或 PQ） │
│    │                          ↓                               │
│    │                   Hash(公钥0) → 地址                      │
│    │                   （这个地址永远不变）                      │
│    │                                                          │
│    ├── SHA256(masterSeed) = Seed0                             │
│    ├── SHA256(Seed0) = Seed1                                  │
│    ├── SHA256(Seed1) = Seed2                                  │
│    ├── ...                                                    │
│    └── SHA256(Seed_{N-1}) = SeedN                             │
│                                                               │
│  使用顺序：SeedN → Seed_{N-1} → ... → Seed1                   │
│  每笔交易消耗一个 Seed，从末端向前回退                           │
│                                                               │
│  每个 Seed_i 派生一对签名密钥（ECDSA 或 PQ），用于当笔交易签名    │
│  签名后该密钥作废，下笔交易使用新 Seed 新密钥                     │
└───────────────────────────────────────────────────────────────┘
```

### 4.2 为什么这样设计——面临的问题与解法

#### 问题一：后量子公钥太大，直接存链上不现实

公钥如果直接存在链上，随着算法不同，体积差异巨大：

| 方案 | 每个 UTXO 链上存储 | 1000 万笔 UTXO | 备注 |
|------|-------------------|---------------|------|
| 直接存 ECDSA P-256 公钥 | 64 字节 | ~0.6 GB | 当前默认 |
| 直接存 PQ 公钥（ML-DSA-65） | 1,952 字节 | ~18.2 GB | 未来可选 |
| **哈希锚点方案（本方案）** | **32 字节** | **~0.3 GB** | **统一** |

**解法：** 链上 UTXO 只存一个 32 字节的 **哈希承诺（anchor）**，不存完整公钥。花钱时才临时亮出完整公钥 + seed 原像来证明归属权。

**为什么即使用 ECDSA 也要用锚点方案？**
1. **前向安全**：每笔交易使用不同密钥，公钥仅在花费瞬间暴露，攻击窗口从"永久"缩短到"交易确认的几秒"。
2. **平滑升级到 PQ**：锚点是 32 字节固定大小，不管底层是 ECDSA（64B 公钥）还是 ML-DSA（1952B 公钥），链上存储结构完全不变。未来切换到 PQ 算法时，只需改变 `seed → keypair` 的派生函数，链上数据格式零改动。
3. **存储节省**：即使 ECDSA 公钥只有 64 字节，锚点也能节省一半。切换到 PQ 后节省 60 倍。

#### 问题二：量子计算机能从公钥推出私钥

经典 ECDSA 公钥一旦在链上公开，量子攻击者可以用 Shor 算法反推私钥。

**解法：** 每笔交易使用不同的密钥签名，公钥只暴露一次就作废。即使攻击者看到了某笔交易的公钥，也无法伪造下一笔交易（因为下一笔用的是完全不同的密钥）。

#### 问题三：换了密钥后链上怎么认

地址不变！地址是从 **masterSeed 派生的公钥** 哈希生成的，永远不变。后续交易的签名公钥虽然在变，但通过 **哈希链承诺** 机制可以证明"新公钥的 seed 和旧公钥的 seed 属于同一条链"。

### 4.3 详细流程

#### 第一步：用户创建新地址

```
输入：
  - 哈希链长度 N（如 1000）
  - 签名算法（默认 "ecdsa_p256"，可选 "pq_ml_dsa")

操作：
  1. 生成主种子（永久保密，永远不在链上暴露）
     masterSeed = RandomBytes(32)

  2. 从主种子派生"地址密钥对"（仅用于确定地址，不用于 UTXO 签名）
     addressKeyPair = DeriveKeyPair(SignAlgorithm, masterSeed)  // 默认 ECDSA P-256
     address = GenerateAddress(addressKeyPair.PublicKey, Type)

  3. 构建哈希链（起点与 masterSeed 隔离，确保链耗尽后地址密钥仍安全）
     seed[0] = SHA256(masterSeed)       // 链的第一个元素
     for i = 1 to N:
         seed[i] = SHA256(seed[i-1])

  4. 计算初始 anchor 承诺（从最高 seed 开始）
     anchor = SHA256(seed[N])

  5. 从 seed[N] 派生第一笔交易将要用的签名密钥（预备）
     currentStep = N
     sigKeyPair = DeriveKeyPair(SignAlgorithm, seed[N])

本地持久化存储：
  {
      address:       "1A2b3C...",
      masterSeed:    masterSeed,             // 主种子（最核心机密，永不暴露）
      chainLength:   N,
      currentStep:   N,                      // 当前使用到哪个 seed
      addressPubKey: addressKeyPair.PublicKey, // 地址公钥（不变）
  }
```

**关键点：**
- `masterSeed` 是用户唯一需要备份的东西。换设备后可重新生成整条链和地址密钥。
- masterSeed 永远不出现在交易中——哈希链从 `seed[0] = SHA256(masterSeed)` 开始。
- 即使链条全部消耗完（最后一步暴露 `seed[0]`），也无法反推 masterSeed，地址私钥永远安全。
- 地址由 masterSeed 的公钥决定，永远不变。
- 每次签名使用 `seed[N]`、`seed[N-1]`、`seed[N-2]`……逐步回退。

#### 第二步：地址注册上链

用户的第一笔交易（Coinbase 或注册交易）在 UTXO 中记录：

```
TXOutput {
    ToAddress:     address,          // 地址（永远不变）
    ToValue:       初始金额,
    ToPublicKey:   addressKeyPair.PublicKey,  // 地址公钥
    SeedAnchor:    SHA256(seed[N]),  // 当前哈希链 anchor 承诺（32 字节）
    SeedChainStep: N,               // 当前步骤号
}
```

**注意：链上不存完整公钥，只存 32 字节的 anchor。花费时才临时亮出公钥。**

#### 第三步：别人给我转账——发送方如何获取接收方的 anchor（核心交互环节）

这是一个关键的实际问题：**发送方构造 TXOutput 时，需要填写接收方的 SeedAnchor 和 SeedChainStep——这些信息从哪来？**

**获取方式分三种场景（按优先级排序）：**

```
场景 1（最常见）：接收方在链上已有 UTXO
  → 发送方查询区块链 UTXO 集，找到接收方地址的任意一个未花费 UTXO
  → 直接复制该 UTXO 上的 SeedAnchor 和 SeedChainStep
  → 不需要和接收方有任何交互！
  → 就像查看别人的 BTC 地址余额一样，这些信息本来就公开在链上

场景 2：接收方刚注册，还没有链上 UTXO（新用户首次收款）
  → 接收方通过钱包软件生成一个 "收款请求"（包含地址 + 初始 anchor + 步骤号）
  → 类似现在微信收款码，只是多携带了锚点信息
  → 或者：接收方加入担保组织时，组织节点自动记录并代为公布 anchor

场景 3：接收方提供一个带 anchor 的收款码/收款链接
  → 钱包 APP 可以生成一个含锚点信息的二维码或链接
  → 格式：pqpay://<address>?anchor=<hex>&step=<N>
  → 发送方扫码即可自动填入
```

**在我们的 UTXO-Area 系统中的适配：** 由于用户加入担保组织时，其 anchor 信息已通过 AssignNode 注册在 StoragePoint 中，组织内转账只需查询 StoragePoint 即可获取最新 anchor，无需额外通信。

#### 第四步：发送交易（花费 UTXO）

假设用户要花掉自己的 UTXO，当前 `currentStep = N`：

```
1. 收集当前步骤的所有 UTXO
   → 必须将同一步骤号的所有 UTXO 一起花掉（"一锅端"）
   → 原因：公开 seed[N] 后该步骤的 anchor 就不再安全，同步骤的所有 UTXO 必须一次性消费

2. 取当前 seed
   currentSeed = seed[N]

3. 从当前 seed 派生签名密钥
   sigKP = DeriveKeyPair(SignAlgorithm, currentSeed)  // ECDSA 或 PQ

4. 构造交易体 txBytes（包含 inputs、outputs 等）

5. 用当前密钥签名
   signature = Sign(SignAlgorithm, sigKP.PrivateKey, txBytes)

6. 计算下一个 anchor（给找零 UTXO 用）
   nextStep = N - 1
   nextAnchor = SHA256(seed[nextStep])

7. 构造 TXInput（解锁旧 UTXO）——每个被花费的 UTXO 对应一个 input
   TXInput {
       FromTXID:       引用的UTXO交易ID,
       FromAddress:    address,
       SeedPublicKey:  sigKP.PublicKey,   // 本次一次性公钥（ECDSA: 64B / PQ: 1952B）
       InputSignature: signature,         // 签名（ECDSA: 64B / PQ: 3309B）
       SeedReveal:     currentSeed,       // 公开当前 seed（32 字节）
       SeedChainStep:  N,                 // 当前步骤号
   }
   // 注意：同一地址的多个 input 共享同一组签名数据（同一个 seed 签的）

8. 构造转账 TXOutput（给接收方）
   TXOutput {
       ToAddress:    receiverAddress,
       ToValue:      转账金额,
       SeedAnchor:   receiverAnchor,      // 从链上查到的接收方锚点
       SeedChainStep: receiverStep,       // 接收方当前步骤号
   }

9. 构造找零 TXOutput（回到自己）
   TXOutput {
       ToAddress:    address,             // 地址不变！
       ToValue:      找零金额,
       SeedAnchor:   nextAnchor,          // 下一个承诺（步骤 N-1）
       SeedChainStep: nextStep,           // 步骤号减 1
   }

10. 本地更新状态
    currentStep = nextStep
```

**为什么要"一锅端"——全额扫描同步骤 UTXO？**

> 一旦 seed[N] 被公开，任何人都知道了这个 seed。虽然旧 UTXO 已被标记为"已花费"不可再用，
> 但如果有其他 UTXO 也锁在同一个 anchor（同一步骤号）上，攻击者也知道对应的 seed。
> 因此必须在公开 seed 的同时，把所有锁在该 anchor 上的 UTXO 全部花掉。

#### 第五步：链上验证逻辑（6 步验证）

验证节点收到交易后，执行以下验证：

```
function VerifyPQTransaction(input, referencedOutput, txBytes):

    // ========== 验证 1：UTXO 存在且未花费 ==========
    if UTXO不存在 or UTXO已花费:
        return FAIL("UTXO 不存在或已花费")

    // ========== 验证 2：地址匹配 ==========
    if input.FromAddress != referencedOutput.ToAddress:
        return FAIL("地址不匹配")

    // ========== 验证 3：哈希链承诺 ==========
    // "亮出的 seed 的哈希 == UTXO 中存的 anchor"
    if SHA256(input.SeedReveal) != referencedOutput.SeedAnchor:
        return FAIL("哈希链承诺不匹配")

    // ========== 验证 4：步骤号一致 ==========
    if input.SeedChainStep != referencedOutput.SeedChainStep:
        return FAIL("哈希链步骤号不一致")

    // ========== 验证 5：公钥与 seed 绑定 ==========
    // 用 seed 重新派生密钥，检查公钥是否一致
    expectedKP = DeriveKeyPair(SignAlgorithm, input.SeedReveal)
    if expectedKP.PublicKey != input.SeedPublicKey:
        return FAIL("公钥与 seed 不匹配")

    // ========== 验证 6：签名验证 ==========
    ok = Verify(SignAlgorithm, input.SeedPublicKey, txBytes, input.InputSignature)
    if !ok:
        return FAIL("签名验证失败")

    return PASS("验证通过")
```

**同一区块内的交易必须逐笔验证并立即应用**（先验证 tx1 → 更新 UTXO 集 → 再验证 tx2），以防止同区块双花攻击。

### 4.4 Seed 暴露安全性分析

#### 核心问题：seed 公开了不危险吗？

**结论：暴露的 seed 是"已经没用的废纸"——有策略地安全。** 下面详细分析。

#### 场景一：正常花费——seed[N] 被公开

```
交易前状态：
  UTXO_A  →  锁在 anchor = SHA256(seed[100])，步骤 100

用户花费 UTXO_A，公开了 seed[100]：
  UTXO_A  →  已花费（从 UTXO 集中删除）
  UTXO_B  →  找零，锁在 anchor = SHA256(seed[99])，步骤 99

攻击者拿到 seed[100] 后能做什么？
  ✗ 重花 UTXO_A？→ 不行，已标记为 "已花费"
  ✗ 花 UTXO_B？ → 需要 seed[99]，但 SHA256 不可逆，从 seed[100] 推不出 seed[99]
  ✗ 算更高编号？→ seed[101] = SHA256(seed[100])，但步骤 101 不存在任何 UTXO
  ✗ 伪造签名？ → 需要和 UTXO 上 anchor 匹配的 seed，攻击者没有

结论：暴露的 seed 对应的 UTXO 已经消失，攻击者拿到了一张"作废的密码纸"。
```

#### 场景二：时序竞争——seed 暴露后有新转入到达

```
时间线：
  ① A 在步骤 100，B 查到 A 的 anchor 是 SHA256(seed[100])
  ② B 构造交易：给 A 转 20 块，UTXO 锁在 步骤 100
  ③ A 自己花了一笔（公开了 seed[100]），A 变成步骤 99
  ④ B 的交易上链 → UTXO_new 锁在步骤 100

问题：seed[100] 已经公开了，UTXO_new 还安全吗？

分析：
  - 攻击者确实知道 seed[100]
  - 但要花 UTXO_new，除了 seed[100]，还需要用 seed[100] 派生的私钥签名
  - A 的钱包也知道 seed[100]，可以立即构造合法交易花掉 UTXO_new

对策：
  - A 的钱包检测到新 UTXO 到达旧步骤时，应自动发起"归集交易"
  - 将该 UTXO 立即转移到当前步骤的 anchor 下
  - 归集交易同样需要签名，攻击者虽然知道 seed 但不知道对应的私钥
    （等等——seed 确定性生成密钥对，知道 seed 就知道私钥！）

重要修正：
  seed[100] 公开 → 攻击者可以用它生成 PQ 公私钥对 → 可以签名！
  
  所以这个 UTXO 确实存在竞争风险！A 和攻击者都能花它！

最终对策（实际部署方案）：
  1. 钱包自动归集：检测到旧步骤的 UTXO 立即广播归集交易
  2. 担保组织协助：在 UTXO-Area 中，担保节点收到交易后会先验证再打包，
     可以优先处理地址所有者的归集请求
  3. 根本解决：发送方在构造交易前，查询链上最新 UTXO 的步骤号，
     确保使用的是接收方的【当前最新步骤】的 anchor，而非已过时的
```

**总结：seed 暴露的唯一风险场景是"发送方使用了过期 anchor"。通过链上查询最新 anchor + 钱包自动归集，可以将风险窗口缩小到接近零。**

#### 场景三：多人同时给 A 转账

```
关键规则：
  所有发送方在转账前，都查询链上 A 的最新 UTXO 步骤号

  如果 A 当前是步骤 100，且没有花费任何钱：
    B 给 A 转 20 → UTXO₁ { anchor=SHA256(seed[100]), step=100 }
    C 给 A 转 15 → UTXO₂ { anchor=SHA256(seed[100]), step=100 }
    D 给 A 转 10 → UTXO₃ { anchor=SHA256(seed[100]), step=100 }

  所有三个 UTXO 都锁在同一个步骤 100 → 完全没问题！
  A 花钱时，一次性扫描步骤 100 的所有 UTXO，用 seed[100] 全部解锁，用 seed[99] 的 anchor 锁找零。

  如果 A 在 B 和 C 之间花了一笔（seed[100] 公开，变步骤 99）：
    UTXO₁ { step=100 } ← A 花钱时已经一起消费了
    UTXO₂ { step=99 }  ← C 查到最新步骤是 99，用了新 anchor
    UTXO₃ { step=99 }  ← D 查到最新步骤是 99，用了新 anchor

  A 下次花钱时，扫描步骤 99 的所有 UTXO 一起花掉即可。
```

### 4.5 同一步骤全额扫描（Sweep）策略

这是本方案与传统 UTXO 模型最大的区别：**花费时必须将同一步骤的所有 UTXO 一次性消费（sweep）**。

#### 为什么必须 sweep？

```
假设 A 在步骤 100 有 3 个 UTXO（共 50 块），只想花 10 块：

  错误做法：只花 1 个 UTXO，剩余 2 个留在步骤 100 不动
  → 公开 seed[100] 后，剩余 2 个 UTXO 的 anchor 对应的 seed 已泄露
  → 攻击者可以用 seed[100] 生成密钥对，抢先花掉剩余 UTXO

  正确做法：3 个 UTXO 全部作为 input 消费（sweep）
  → 转出 10 块
  → 找零 40 块（减手续费）→ 锁到步骤 99 的 anchor
  → seed[100] 对应的 UTXO 全部清空，泄露 seed[100] 零风险
```

#### Sweep 策略的流程

```
1. 查出该地址最高步骤号的所有 UTXO
2. 全部作为 TXInput
3. 构造 TXOutput（转账+找零）
4. 签名（同一组 seed/密钥签所有 input）
5. 找零 UTXO 锁到下一步骤（currentStep-1）
```

#### 不同步骤号 UTXO 的处理（由高到低依次花费）

由于用户可能在不同时间收到锁在不同步骤号的 UTXO：

```
A 持有的 UTXO：
  UTXO₁: step=100, 金额=30  ← 锁在 SHA256(seed[100])
  UTXO₂: step=99,  金额=20  ← 锁在 SHA256(seed[99])
  UTXO₃: step=99,  金额=10  ← 锁在 SHA256(seed[99])

花费顺序：
  第 1 次花钱 → 扫描步骤 100 的 UTXO（UTXO₁），找零锁到步骤 99
  第 2 次花钱 → 扫描步骤 99 的所有 UTXO（UTXO₂ + UTXO₃ + 第 1 次的找零），找零锁到步骤 98

规则：永远从最高步骤号开始花费，逐步向下。
```

### 4.6 哈希链回退的安全性证明

```
正向构建：
  seed[0] → H → seed[1] → H → seed[2] → ... → H → seed[N]
  容易：知道 seed[i]，可算出 seed[i+1] = H(seed[i])

反向回退（使用方向）：
  seed[N] → seed[N-1] → seed[N-2] → ... → seed[1]
  不可能：知道 seed[i+1]，无法反推 seed[i]

使用时序：
  第 1 笔交易 → 用 seed[N]   → 公开 seed[N]
  第 2 笔交易 → 用 seed[N-1] → 公开 seed[N-1]
  第 3 笔交易 → 用 seed[N-2] → 公开 seed[N-2]
  ...
  第 N 笔交易 → 用 seed[1]   → 公开 seed[1]
```

**安全性保障三重机制：**

1. **前向安全（Forward Security）**：攻击者看到 `seed[N]`，无法计算 `seed[N-1]`（SHA256 不可逆）。未来的交易使用的是低编号 seed，从高编号推不出低编号。
2. **无密钥重用（No Key Reuse）**：每笔交易的签名密钥完全不同。即使某一笔的密钥被量子计算机破解，也不影响其他交易（因为其他交易用的是完全不同的密钥对）。
3. **承诺不可伪造（Commitment Integrity）**：UTXO 中的 `anchor = SHA256(seed[i])` 在上一笔交易上链时已确认。攻击者无法修改已确认区块的内容来替换 anchor。

### 4.7 Seed 链的管理与备份策略

#### 本地存储结构

```json
{
    "address": "1A2b3CxyzDEF...",
    "algorithm": "ecdsa_p256",
    "masterSeed": "a3f2b1c4...(32字节hex)",
    "chainLength": 1000,
    "currentStep": 997,
    "addressPublicKey": "8f3a2b...(64字节hex)"
}
```

#### 备份与恢复

用户只需备份以下信息即可完整恢复：

| 备份项 | 大小 | 必要性 | 说明 |
|-------|------|-------|------|
| `masterSeed` | 32 字节 | **必须** | 主种子，可重新生成整条链和地址密钥 |
| `chainLength` | 整数 | **必须** | 链长度 |
| `currentStep` | 整数 | **必须** | 当前用到哪一步 |
| `algorithm` | 字符串 | **必须** | 使用的算法名 |

恢复流程：
```
1. 从 masterSeed 派生地址密钥 → 恢复地址
2. seed[0] = SHA256(masterSeed)，然后重新计算 seed[1..N]
3. 从 currentStep 对应的 seed 重新派生当前签名密钥
4. 继续正常使用
```

**重要提示：** 如果用户备份了 masterSeed 但丢失了 currentStep，可以通过扫描区块链恢复——找到该地址最近一笔交易中公开的步骤号即为已使用的最后步骤，currentStep = 该步骤号 - 1。

#### masterSeed 的加密保护

```go
// 用 Keystore 加密保护 masterSeed
encrypted, _ := walletcrypto.EncryptPrivateKey(masterSeed, []byte("用户密码"))
// 存储 encrypted 到磁盘

// 恢复时解密
masterSeed, _ := walletcrypto.DecryptPrivateKey(encrypted, []byte("用户密码"))
```

### 4.8 Seed 链耗尽与续链策略

#### 何时触发

当 `currentStep` 减到 0 时（seed[0] 已暴露，但 masterSeed 仍安全），链即耗尽。

#### 耗尽保护机制

```
当用户在最后一步（步骤 1）发起交易时：
  - 如果需要找零 → 拒绝交易，提示"种子链即将耗尽，请先续链或全额转出"
  - 如果恰好全额花完（无需找零）→ 允许（因为不需要新 anchor）
  - 剩余步骤 < 10 时 → 钱包弹窗警告"剩余签名次数不足，请尽快续链"
```

#### 续链方案 A：在同一地址上续链（推荐）

```
1. 在步骤号还充裕时（如 currentStep > 5），发起"续链交易"（TXType = 专用续链类型）
2. 续链交易的语义：
   - 用当前 seed[step] 签名，证明身份
   - 交易附带: newChainAnchor = SHA256(newSeed[M])，其中 M 是新链长度
   - 新链的 newMasterSeed 派生规则：newMasterSeed = HMAC-SHA256(seed[currentStep], "PANGU_CHAIN_RENEW_V1")
3. 找零 UTXO 用新链的 anchor 锁定
4. 从此以后，该地址用新链的 seed 签名
5. 地址永不改变

验证节点额外检查：
  - 续链交易必须包含合法的旧链签名（证明是地址所有者发起）
  - 新链 anchor 记录在链上，后续交易基于新链验证
```

#### 续链方案 B：转移到新地址

```
1. 生成全新的 masterSeed'，全新的地址
2. 将旧地址资产全额转到新地址
3. 旧地址退休，新地址启用
```

**方案 A 优势：** 地址不变，合约/联系人不需要更新。
**方案 B 优势：** 实现简单，不需要链上协议支持"续链"交易类型。

### 4.9 实际部署中的关键问题与对策

#### 问题一：用户不能同时构造两笔交易

```
原因：
  两笔交易都会试图使用同一个 seed[currentStep]，
  但 seed 只能用一次——第二笔交易的 anchor 验证会失败。

对策：
  - 钱包层面加锁：上一笔交易确认前，禁止发起新交易
  - 或者：在 UTXO-Area 的 TXCer 快速确认机制下，等待 TXCer 到达（毫秒级）再发下一笔
  - 或者：一次构造多输出交易（一笔交易包含多个接收方），避免需要多笔
```

#### 问题二：交易未上链时的状态问题

```
场景：用户发起交易后，交易在内存池排队，还没上链

问题：
  - 用户本地已将 currentStep 从 100 更新到 99
  - 但链上 UTXO 还是步骤 100 的 anchor
  - 如果交易因某种原因被丢弃（网络故障等），状态不一致

对策：
  - 钱包记录"待确认交易"列表
  - 如果交易超时未确认，回滚本地 currentStep
  - 由于 seed 链是确定性的，回滚不会丢失数据，只是重置步骤号
```

#### 问题三：同一区块内的双花防护

```
攻击场景：
  攻击者提交两笔交易都花费同一个 UTXO，试图在同一区块中双花

对策（已在模拟器中实现并验证）：
  区块打包时，逐笔验证 + 立即应用（而不是先全部验证再全部应用）
  → 第一笔验证通过 → UTXO 标记已花费
  → 第二笔验证时发现 UTXO 已花费 → 拒绝
```

#### 问题四：隐私考量——步骤号泄露信息

```
问题：
  UTXO 上的 SeedChainStep 暴露了"该地址已完成多少笔交易"
  例如 step=950 说明这个地址已经从 1000 步花了 50 笔

对策：
  方案 A（简单）：接受这个信息泄露，它只暴露交易笔数，不暴露金额
  方案 B（增强）：将 SeedChainStep 改为加密存储，只有地址所有者能解读
    - anchor 本身不需要步骤号即可验证（SHA256(seed) == anchor 就行）
    - 步骤号主要是方便钱包管理，可以从 anchor 本身隐式推导
  方案 C（进一步）：在找零 UTXO 中不存储明文步骤号，而是存储
    encryptedStep = AES-GCM(step, key=SHA256(seed[0] || "STEP_ENCRYPT"))
    只有知道 seed[0] 的人能解密出步骤号
```

#### 问题五：发送方使用过期 anchor 的防护

```
这是 4.4 节"时序竞争"场景的工程化对策：

1. 钱包层面：
   - 构造交易前，实时查询链上最新 UTXO 集
   - 如果查到的步骤号与缓存不同，自动刷新

2. 节点层面（UTXO-Area 特有）：
   - AssignNode 在收到交易后，检查 TXOutput 中的 receiverAnchor
   - 如果与链上最新不匹配，返回错误提示发送方刷新
   - 或者：AssignNode 自动修正为最新 anchor（需要协议支持）

3. 接收方层面：
   - 钱包后台定期检查是否有锁在旧步骤号的 UTXO
   - 如果有，自动发起归集交易，将其转移到当前步骤
   - 归集交易本身消耗一个 seed 步骤，但保证资金安全
```

#### 问题六：钱包软件崩溃/丢失后的恢复

```
最坏情况：用户只有 masterSeed 和 chainLength，丢失了 currentStep

恢复流程：
  1. 从 masterSeed 重建完整 seed 链
  2. 扫描区块链，找到该地址最后一笔交易
  3. 从该交易的 TXInput.SeedChainStep 读取已使用的步骤号
  4. currentStep = 该步骤号 - 1
  5. 恢复完成

如果区块链上找不到该地址的任何交易（从未用过）：
  → currentStep = chainLength（初始值）
```

### 4.10 方案取舍总结：锚点方案 vs 直接存公钥

| 对比维度 | 锚点方案（本文方案） | 直接存公钥 |
|---------|-------------------|---------------|
| **链上存储** | 32 字节/UTXO | ECDSA: 64B / PQ: 1,952B |
| **发送方体验** | 需要知道 anchor（可链上查询） | 只需地址即可 |
| **花费方式** | 同步骤 UTXO 全额扫描 | 随意选择任意 UTXO |
| **公钥暴露时间** | 仅花费瞬间 | 永久暴露在链上 |
| **前向安全** | ✅ 内建（每次不同密钥） | ✖ 需要额外机制 |
| **PQ 升级成本** | ✅ 零改动（仅换派生函数） | ✖ 链上存储结构需改 |
| **实现复杂度** | 较高 | 较低 |
| **适用场景** | 高安全要求 + 需要 PQ 升级路径 | 小规模链或无 PQ 需求 |

**我们选择锚点方案**，因为它提供了内建的前向安全性，并且为未来平滑切换到后量子算法铺好了基础设施。当前阶段使用 ECDSA 密钥不影响方案架构，未来只需替换 `DeriveKeyPair` 实现即可升级。

### 4.11 Seed 链与密码库 API 的映射关系

| 方案步骤 | 对应密码库 API（默认 ECDSA） | 后量子可选 |
|---------|-------------------------------|----------|
| 生成 masterSeed | `walletcrypto.RandomBytes(32)` | 同 |
| 构建哈希链 | `walletcrypto.HashData("sha256", seed[i])` 循环 | 同 |
| 从 masterSeed 派生地址密钥 | `walletcrypto.DeriveKeyPairFromSeed("ecdsa_p256", masterSeed)` | 改为 `"pq_ml_dsa"` |
| 生成地址 | `walletcrypto.GenerateAddress(pk, opts)` | 同 |
| 从 seed[i] 派生签名密钥 | `walletcrypto.GenerateKeyPairWithSeed("ecdsa_p256", seed[i])` | 改为 `"pq_ml_dsa"` |
| 签名 | `walletcrypto.SignMessage("ecdsa_p256", sk, txBytes)` | 改为 `"pq_ml_dsa"` |
| 验签 | `walletcrypto.VerifyMessage("ecdsa_p256", pk, txBytes, sig)` | 改为 `"pq_ml_dsa"` |
| 计算 anchor | `walletcrypto.HashData("sha256", seed[i])` | 同 |
| 验证 anchor | `SHA256(seedReveal) == anchor` | 同 |
| 加密 masterSeed | `walletcrypto.EncryptPrivateKey(masterSeed, password)` | 同 |
| 解密 masterSeed | `walletcrypto.DecryptPrivateKey(encrypted, password)` | 同 |
| 续链派生 | `walletcrypto.HMACSHA256(seed[step], "PANGU_CHAIN_RENEW_V1")` | 同 |

> **切换策略：** 只需将上表“后量子可选”列的算法名替换到配置中，链上存储格式（anchor）完全不变。

---


## 五、UTXO-Area 转账区全面改造方案（纯 Seed 链模式 · 最终实施版）

> **核心前提：** 系统从底层全面切换到 Seed 链一次性密钥模式，UTXO 花费签名全部走 Seed 链一次性密钥。
> 身份认证 / 授权类签名保留永久 ECDSA 账户密钥（`AccountPrivateKey`），不走 Seed 链。
> **唯一例外：** AggretionNode 管理的组织质押账户（`IsGuarMake=true`）使用组织密钥签名。

### 5.1 核心设计原则

1. **双层密钥体系**：系统中存在两类用户密钥，各司其职（见 5.1A 签名分类总表）：
   - **账户密钥**（`AccountPrivateKey` / `AccountPublicKey`）：永久 ECDSA 密钥对，用于身份认证与授权
   - **Seed 链一次性密钥**：每个子地址绑定一条 Seed 链，仅用于 UTXO 花费签名（`InputSignature`）
2. **Per-UTXO 锚点**：每个 UTXO 携带自己的 `SeedAnchor` 和 `SeedChainStep`，验证以 UTXO 为单位
3. **同步骤全扫（Sweep）**：同一步骤号的所有 UTXO 必须在同一笔交易中全部消费（因为暴露 seed 后该步骤的所有 UTXO 均可被攻击者花费）
4. **masterSeed 永久保密**：地址密钥由 masterSeed 派生；哈希链从 `seed[0] = SHA256(masterSeed)` 开始，链条耗尽后 seed[0] 被暴露但无法反推 masterSeed，地址私钥永远安全
5. **组织特权例外**：AggretionNode 管理的质押/奖励 UTXO（`IsGuarMake=true`）使用固定组织密钥签名，不走 Seed 链
6. **密码库统一**：所有密钥操作通过 `CryptoArea/crypto/walletcrypto` 包完成
7. **算法可切换**：当前默认 `ecdsa_p256`，未来修改配置参数即可切换到 `pq_ml_dsa`，数据结构无需改动

### 5.1A 签名分类总表（密钥使用规范）

> **核心结论：** 整个系统中只有 `TXInput.InputSignature`（UTXO 花费签名）需要使用 Seed 链一次性密钥。
> 其余所有签名均使用永久 ECDSA 密钥（账户密钥或节点密钥），不涉及 Seed 链。

#### A 类：永久 ECDSA 账户密钥签名（`AccountPrivateKey`）— 不需要 Seed 链

这些签名本质上是 **身份认证 / 授权行为**，跟 UTXO 所有权无关：

| 场景 | 代码位置 | 签名字段 | 说明 |
|------|---------|---------|------|
| 新建子地址通知 | `wallet/user.go:91` | `UserNewAddressInfo.Sig` | 告诉 AssignNode "我开了新地址" |
| **TX 用户签名** | `wallet/user.go:523` | `Transaction.UserSignature` | **[CHANGED] 整笔交易的用户授权签名，改为账户密钥** |
| **TXCer 用户签名** | `wallet/user.go:430` | `TxCertificate.UserSignature` | **[CHANGED] 即时凭证的用户授权签名，改为账户密钥** |
| 发送 TX 信封 | `wallet/user.go:606` | `UserNewTX.Sig` | 把交易包裹发给 AssignNode 的外层签名 |
| 加入担保组织 | `wallet/user.go:674` | `UserFlowMsg.UserSig` | 加入组织申请 |
| 退出担保组织 | `wallet/user.go:725` | `UserFlowMsg.UserSig` | 退出组织申请 |
| 重新上线 | `wallet/login.go:138` | `UserReOnlineMsg.Sig` | 断线重连身份验证 |
| 地址解绑 | `wallet/handle.go:710` | `UserAddressBindingMsg.Sig` | 解除地址绑定 |
| 地址重绑 | `wallet/handle.go:800` | `UserAddressBindingMsg.Sig` | 重新绑定地址 |

#### B 类：Seed 链一次性密钥签名 — 需要改造

这些签名本质上是 **证明 UTXO 所有权**，必须使用 Seed 链派生的一次性密钥：

| 场景 | 代码位置 | 签名字段 | 当前用的 key | 改造后用的 key |
|------|---------|---------|-------------|---------------|
| UTXO 花费签名 | `wallet/user.go:376` | `TXInput.InputSignature` | `WPrivateKey` | Seed 链一次性私钥 |

**关键验证逻辑**（`GuarNode/guarantor.go:768`）：
```go
// 现有代码：用 output.ToPublicKey 验证 InputSignature
sig := input.InputSignature
pubkey := output.ToPublicKey
hash, _ := output.GetTXOutputHash()
result = core.VerifyHash(hash[:], sig, core.ConvertToPublicKey(pubkey))
```
改造后 `output.ToPublicKey` 存储的是 Seed 链一次性公钥（5.8.1 VerifyUTXOSig 详细流程）。

#### C 类：节点永久密钥签名 — 不需要改动

所有节点使用各自的永久 ECDSA 私钥签名，与 Seed 链完全无关：

| 节点类型 | 私钥变量名 | 签名场景 |
|---------|-----------|----------|
| GuarNode | `GuarPrivatekey` | TX 验证结果、流程消息 |
| AggretionNode | `AggrPrivatekeyNew` | TXCer.GuarGroupSignature、聚合 TX 签名 |
| AssignNode | `AssiPrivatekeyNew` | 管理消息、地址注册确认 |
| CommitteeNode | `CommPrivateKeyNew` | 区块签名、快照签名 |

#### 设计理由：TX.UserSignature 和 TXCer.UserSignature 为什么改用 AccountPrivateKey

1. **本质是授权行为**：TX.UserSignature 代表"我（账户持有者）授权这笔交易"，TXCer.UserSignature 代表"我（账户持有者）预授权即时支付"——这些是身份层面的授权，不是 UTXO 所有权证明
2. **双层安全**：改造后每笔交易需要两个独立的签名才能通过验证：
   - `InputSignature`（Seed 链一次性密钥）→ 证明 UTXO 所有权
   - `TX.UserSignature`（AccountPrivateKey）→ 证明账户授权
   即使一次性密钥因量子攻击被破解，没有 AccountPrivateKey 仍无法伪造完整交易
3. **简化 TXCer 结构**：TXCer.UserSignature 不再需要 SeedReveal / SeedPublicKey / SeedChainStep 字段，结构更简洁
4. **验证端改动极小**：GuarNode 已有 `UserInfo[userID].AccountPublicKey`，只需将 `VerifyTXUserSignature` 的公钥来源从 `SubAddressMsg[addr].PublicKeyNew` 改为 `UserInfo[userID].AccountPublicKey`

### 5.2 Seed 链核心机制回顾（实施参考）

```
一条 Seed 链的完整生命周期：

创建：
  masterSeed = RandomBytes(32)                 // 永久保密
  addressKP  = DeriveKeyPair("ecdsa_p256", masterSeed)
  address    = GenerateAddress(addressKP.PublicKey, Type)
  seed[0]    = SHA256(masterSeed)              // 链起点（最后一步才暴露，但不暴露 masterSeed）
  seed[i]    = SHA256(seed[i-1])  for i=1..N
  anchor     = SHA256(seed[N])                 // 初始锚点，公开注册

消费（从步骤 N 逐步递减到 1）：
  第 k 次消费（currentStep = N-k+1）：
    revealSeed  = seed[currentStep]            // 暴露当前步骤的 seed
    oneTimeKP   = DeriveKeyPair("ecdsa_p256", revealSeed)
    signature   = Sign(oneTimeKP.PrivateKey, txData)
    验证: SHA256(revealSeed) == UTXO.SeedAnchor
    找零 anchor = SHA256(seed[currentStep-1])  // 下一步骤的承诺

安全性：
  - 暴露 seed[k] → 可正向计算 seed[k+1], seed[k+2], ... → 这些步骤的 UTXO 已经被消费
  - 无法反向计算 seed[k-1] → 未来步骤的 UTXO 安全
  - 无法从 seed[0] 反推 masterSeed → 地址密钥永远安全

容量：N 次消费后链耗尽，需要续链（见 5.14）
```

### 5.3 核心数据结构完整定义

> 以下是所有需要改造的数据结构的 **完整字段定义**。标 `[NEW]` 的为新增字段，标 `[CHANGED]` 的为语义变更字段，其余为现有字段保留。

#### 5.3.1 TXInputNormal（交易输入 — 花费 UTXO）

```go
type TXInputNormal struct {
    FromAddress    string          // 花费地址
    FromTXID       string          // 引用的 UTXO 所在交易 ID
    FromIndex      int             // 引用的 UTXO 在交易中的索引
    InputSignature EcdsaSignature  // [CHANGED] 用 seed 链派生的一次性私钥签名
    SeedReveal     []byte          // [NEW] 暴露的 seed 值（32 字节）
    SeedPublicKey  PublicKeyNew    // [NEW] 从 SeedReveal 派生的一次性公钥
    SeedChainStep  int             // [NEW] 消费的步骤号（= UTXO 的 SeedChainStep）
}
```

**设计说明：**
- `InputSignature`：签名内容不变（仍为 UTXO.Output 的哈希），但签名密钥从"地址私钥"变为"seed 链一次性私钥"
- `SeedReveal`：核心安全要素——`SHA256(SeedReveal)` 必须等于被花费 UTXO 的 `SeedAnchor`
- `SeedPublicKey`：冗余但有用——验证端可从 `SeedReveal` 重新派生来做一致性检查
- 同一地址的多个 TXInput 共享相同的 `SeedReveal` / `SeedPublicKey`（同一步骤的同一 seed）

#### 5.3.2 TXOutput（交易输出 — 创建 UTXO）

```go
type TXOutput struct {
    ToAddress     string          // 接收地址
    ToValue       float64         // 金额
    ToGuarGroupID string          // 所属担保组织 ID
    ToPublicKey   PublicKeyNew    // 接收方地址公钥（从 masterSeed 派生，终身不变）
    ToInterest    float64         // 利息
    Type          int             // 地址类型
    ToPeerID      string          // P2P 节点 ID
    IsPayForGas   bool            // 是否手续费
    IsCrossChain  bool            // 是否跨链
    IsGuarMake    bool            // 是否组织管理（质押/奖励/担保修改）
    SeedAnchor    []byte          // [NEW] 该 UTXO 的哈希链锚点
    SeedChainStep int             // [NEW] 该 UTXO 的步骤号
}
```

**各场景下 SeedAnchor / SeedChainStep 的填写规则：**

| 场景 | SeedAnchor | SeedChainStep |
|------|-----------|---------------|
| 转账给他人 | 接收方当前最高步骤的锚点（从 StoragePoint 查） | 接收方当前最高步骤号 |
| 找零给自己 | `SHA256(seed[currentStep-1])`（下一步骤的承诺） | `currentStep - 1` |
| 组织管理 UTXO（IsGuarMake=true 且在质押地址上） | `nil` | `0` |
| 利息/退押发到用户地址 | 从 StoragePoint 查用户当前 anchor | 用户当前 step |

#### 5.3.3 TxCertificate（TXCer — 即时确认凭证）

```go
type TxCertificate struct {
    TXCerID            string          // 凭证唯一 ID
    ToAddress          string          // 归属地址
    ToGuarGroupID      string          // 所属担保组织
    Value              float64         // 金额
    GuarGroupSignature EcdsaSignature  // 组织签名（AggretionNode 出具）
    UserSignature      EcdsaSignature  // [CHANGED] 改用 AccountPrivateKey 签名（身份授权）
}
```

**v5.1 变更说明：**
- `UserSignature` 改用 `AccountPrivateKey` 签名，不再使用 Seed 链一次性密钥
- **移除** `SeedReveal`、`SeedPublicKey`、`SeedChainStep` 字段（TXCer 签名是授权行为，不涉及 UTXO 所有权证明）
- 验证端使用 `UserInfo[userID].AccountPublicKey` 验证（见 5.9.3）

#### 5.3.4 PointAddressData（StoragePoint 中的地址数据）

```go
type PointAddressData struct {
    Value         float64                // 总余额
    Type          int                    // 地址类型
    Interest      float64                // 累计利息
    GroupID       string                 // 所属担保组织 ID
    PublicKeyNew  PublicKeyNew           // 地址公钥（终身不变）
    UTXO          map[string]UTXOData    // UTXO 集合
    LastHeight    uint64                 // 最后更新区块高度
    SeedAnchor    []byte                 // [NEW] 该地址当前最高步骤的锚点
    SeedChainStep int                    // [NEW] 该地址当前最高步骤号
}
```

**锚点更新规则（由 `GetStoragePoint()` 维护）：**
- 该地址有消费（TXInput）→ 锚点从找零输出获取（步骤号减小）
- 该地址首次出现（新地址）→ 锚点从 TXOutput 初始化
- 该地址收到他人转账 → 锚点不变（只增加 UTXO，不改 anchor）

#### 5.3.5 wallet.AddressData（钱包本地地址数据）

```go
// wallet/account.go
type AddressData struct {
    // === 现有字段 ===
    WPublicKey   ecdsa.PublicKey         // 地址公钥（从 masterSeed 派生）
    WPrivateKey  ecdsa.PrivateKey        // 地址私钥（从 masterSeed 派生，不再用于链上签名，仅保留用于地址派生验证）
    UTXO         map[string]core.UTXOData
    Type         int
    TXCers       map[string]float64
    Value        core.Value
    EstInterest  float64
    // === [NEW] Seed 链状态 ===
    MasterSeed   []byte                 // 主种子（加密存储，永不暴露）
    ChainLength  int                    // 链长度 N
    CurrentStep  int                    // 当前可用步骤号（从 N 开始递减）
    SeedCache    [][]byte               // 预计算的全部 seed 值（N=1000 时占 32KB）
}
```

#### 5.3.6 UserNewAddressInfo / UserNewAddressNotify

```go
// core/guargroup.go
type UserNewAddressInfo struct {
    NewAddress    string
    PublicKeyNew  PublicKeyNew
    UserID        string
    Type          int
    Sig           EcdsaSignature
    SeedAnchor    []byte          // [NEW] 初始锚点 = SHA256(seed[N])
    SeedChainStep int             // [NEW] 初始步骤号 = N
}

type UserNewAddressNotify struct {
    GuarGroupID   string
    NewAddress    string
    PublicKeyNew  PublicKeyNew
    UserID        string
    Type          int
    Sig           EcdsaSignature
    SeedAnchor    []byte          // [NEW]
    SeedChainStep int             // [NEW]
}
```

#### 5.3.7 NodeMsg / UserAddressBindingMsg

```go
// core/guargroup.go — 用户在组织内的记录
type NodeMsg struct {
    GuarID       string
    AccountID    string
    PeerID       string
    PublicKeyNew PublicKeyNew
    NodeAddress  string
    SeedAnchor    []byte   // [NEW] 当前锚点
    SeedChainStep int      // [NEW] 当前步骤号
}

// core/address_binding.go — 地址绑定/解绑消息
type UserAddressBindingMsg struct {
    Op        int
    UserID    string
    Address   string
    PublicKey PublicKeyNew
    Type      int
    TimeStamp uint64
    Sig       EcdsaSignature
    SeedAnchor    []byte   // [NEW] 重绑时提供锚点
    SeedChainStep int      // [NEW] 重绑时提供步骤号
}
```

#### 5.3.8 FlowAddressData（加入组织时的地址数据）

```go
type FlowAddressData struct {
    AddressData struct {
        PublicKeyNew  PublicKeyNew
        Type          int
        SeedAnchor    []byte   // [NEW]
        SeedChainStep int      // [NEW]
    }
}
```

### 5.4 密码库集成点

所有密钥操作统一通过 `CryptoArea/crypto/walletcrypto` 包完成：

```go
import "github.com/panguPay/CryptoArea/crypto/walletcrypto"

// ① masterSeed 生成
masterSeed := walletcrypto.RandomBytes(32)

// ② 地址密钥对派生
addressKP, err := walletcrypto.DeriveKeyPairFromSeed("ecdsa_p256", masterSeed)

// ③ 地址生成
address := walletcrypto.GenerateAddress(addressKP.PublicKey, opts)

// ④ 哈希链构建
seed0 := walletcrypto.HashData("sha256", masterSeed)
seedI := walletcrypto.HashData("sha256", seedPrev)

// ⑤ 一次性密钥派生（消费时）
oneTimeKP, err := walletcrypto.DeriveKeyPairFromSeed("ecdsa_p256", revealSeed)

// ⑥ 签名
sig, err := walletcrypto.SignMessage("ecdsa_p256", oneTimeKP.PrivateKey, txOutputHash)

// ⑦ 验签
ok, err := walletcrypto.VerifyMessage("ecdsa_p256", oneTimeKP.PublicKey, txOutputHash, sig)

// ⑧ anchor 计算
anchor := walletcrypto.HashData("sha256", seed)

// ⑨ masterSeed 加密存储
encrypted := walletcrypto.EncryptPrivateKey(masterSeed, userPassword)
decrypted := walletcrypto.DecryptPrivateKey(encrypted, userPassword)
```

**walletcrypto 需要新增的函数：**

```go
// DeriveKeyPairFromSeed 从任意 32 字节 seed 确定性派生密钥对
// 内部实现：seed → HMAC-DRBG 或 SHA256 → 私钥 scalar (mod n) → 公钥 = scalar × G
func DeriveKeyPairFromSeed(algorithm string, seed []byte) (*KeyPair, error)
```

### 5.5 地址创建与 Seed 链初始化

#### 5.5.1 wallet/user.go — NewSubAddress 完整改造

```go
func (a *Account) NewSubAddress(addrType int, chainLength int) (string, error) {
    if chainLength <= 0 {
        chainLength = 1000  // 默认链长度
    }

    // 1. 生成主种子
    masterSeed := walletcrypto.RandomBytes(32)

    // 2. 派生地址密钥对
    addressKP, err := walletcrypto.DeriveKeyPairFromSeed("ecdsa_p256", masterSeed)
    if err != nil {
        return "", err
    }

    // 3. 生成地址（现有逻辑不变）
    address := core.GenerateAddress(addressKP.PublicKey, addrType)

    // 4. 构建哈希链（预计算全部 seed）
    seeds := make([][]byte, chainLength+1)
    seeds[0] = walletcrypto.HashData("sha256", masterSeed) // seed[0] = SHA256(masterSeed)
    for i := 1; i <= chainLength; i++ {
        seeds[i] = walletcrypto.HashData("sha256", seeds[i-1])
    }

    // 5. 计算初始 anchor
    initialAnchor := walletcrypto.HashData("sha256", seeds[chainLength])

    // 6. 存入钱包
    a.Wallet.AddressMsg[address] = AddressData{
        WPublicKey:   addressKP.PublicKey,
        WPrivateKey:  addressKP.PrivateKey,
        UTXO:         make(map[string]core.UTXOData),
        Type:         addrType,
        TXCers:       make(map[string]float64),
        Value:        core.Value{},
        MasterSeed:   masterSeed,
        ChainLength:  chainLength,
        CurrentStep:  chainLength,  // 从最高步骤开始
        SeedCache:    seeds,        // 缓存全部 seed（32KB for N=1000）
    }

    // 7. 如果已加入担保组织，通知 AssignNode
    if a.GuarantorGroupID != "" {
        msg := core.UserNewAddressInfo{
            NewAddress:    address,
            PublicKeyNew:  core.ConvertToPublicKeyNew(addressKP.PublicKey, "P256"),
            UserID:        a.AccountID,
            Type:          addrType,
            SeedAnchor:    initialAnchor,
            SeedChainStep: chainLength,
        }
        sig, _ := core.SignStruct(msg, a.AccountPrivateKey, "Sig")
        msg.Sig = sig
        a.PeerNode.UnicastP2P(a.GuarGroupBootMsg.AssiPeerID, MsgType_UserNewAddress, msg)
    }

    return address, nil
}
```

#### 5.5.2 辅助函数：获取 seed

```go
// getSeedAtStep 获取 seed[step]
// 优先从缓存读取，否则即时计算
func (ad *AddressData) getSeedAtStep(step int) []byte {
    if ad.SeedCache != nil && step >= 0 && step < len(ad.SeedCache) {
        return ad.SeedCache[step]
    }
    // 即时计算：从 masterSeed 开始哈希 step+1 次
    current := walletcrypto.HashData("sha256", ad.MasterSeed) // seed[0]
    for i := 1; i <= step; i++ {
        current = walletcrypto.HashData("sha256", current)
    }
    return current
}
```

### 5.6 用户加入担保组织（JoinGroup）

#### 5.6.1 完整交互流程

```
用户钱包                        AssignNode                     StoragePoint
   │                               │                               │
   │  FlowApplyRequest             │                               │
   │  {                            │                               │
   │    UserID, GuarGroupID,       │                               │
   │    UserPublicKey(账户公钥),   │                               │
   │    AddressMsg: {              │                               │
   │      地址A: {                 │                               │
   │        PublicKeyNew,          │                               │
   │        SeedAnchor,            │                               │
   │        SeedChainStep,         │                               │
   │      },                       │                               │
   │      地址B: { ... },          │                               │
   │    },                         │                               │
   │    UserSig(账户私钥签名)      │                               │
   │  }                            │                               │
   ├──────────────────────────────►│                               │
   │                               │  VerFlowAddressMsg()          │
   │                               │  ─ 验证 GenerateAddress =     │
   │                               │    PublicKeyNew → 地址一致    │
   │                               │  ─ 若 StoragePoint 已有，     │
   │                               │    验证 PublicKeyNew 一致      │
   │                               │  ─ 验证 SeedAnchor 为 32 字节 │
   │                               │  ─ SeedChainStep > 0          │
   │                               │  ─ 检查无组织冲突             │
   │                               ├─────────────────────────────►│
   │                               │                               │
   │                               │  AddFlowAddressMsg()          │
   │                               │  ─ 写入 GroupID               │
   │                               │  ─ 写入 PublicKeyNew          │
   │                               │  ─ 写入 SeedAnchor,           │
   │                               │    SeedChainStep              │
   │                               │                               │
   │                               │  注册 UserMessage、UserInfo   │
   │                               │  广播 UserTXInfoInc           │
   │   FlowApplyReply              │                               │
   │ ◄─────────────────────────── │                               │
```

#### 5.6.2 AssignNode 改造要点

```go
// VerFlowAddressMsg 增加 anchor 验证
func (s *StoragePoint) VerFlowAddressMsg(...) (float64, error) {
    for address, data := range AddressMsg {
        // [NEW] 验证 anchor 格式
        if len(data.AddressData.SeedAnchor) != 32 {
            return 0, fmt.Errorf("address %s: SeedAnchor must be 32 bytes", address)
        }
        if data.AddressData.SeedChainStep <= 0 {
            return 0, fmt.Errorf("address %s: SeedChainStep must be positive", address)
        }

        // [NEW] 若 StoragePoint 已有此地址，验证 anchor 一致
        if point, ok := s.PointAddressMsg[address]; ok && len(point.SeedAnchor) > 0 {
            if !bytes.Equal(point.SeedAnchor, data.AddressData.SeedAnchor) {
                return 0, fmt.Errorf("address %s: SeedAnchor mismatch with StoragePoint", address)
            }
        }
        // ... 现有验证（公钥匹配、组织冲突检查）保持不变 ...
    }
}

// AddFlowAddressMsg 存储 anchor
func (s *StoragePoint) AddFlowAddressMsg(...) error {
    for address, data := range AddressMsg {
        if _, exists := s.PointAddressMsg[address]; !exists {
            // 新地址：完整初始化（含 anchor）
            s.PointAddressMsg[address] = PointAddressData{
                PublicKeyNew:  data.AddressData.PublicKeyNew,
                GroupID:       GuarGroupID,
                SeedAnchor:    data.AddressData.SeedAnchor,
                SeedChainStep: data.AddressData.SeedChainStep,
                UTXO:          make(map[string]UTXOData),
                // ... Value, Type, Interest 初始化 ...
            }
        } else {
            // 已知地址：只更新 GroupID
            temp := s.PointAddressMsg[address]
            temp.GroupID = GuarGroupID
            s.PointAddressMsg[address] = temp
        }
    }
}
```

#### 5.6.3 前端 FlowApply 改造

```typescript
// PanguPayExtension / TransferAreaInterface
const addressMsg: Record<string, FlowAddressData> = {};
for (const [addr, data] of Object.entries(wallet.addressMsg)) {
    addressMsg[addr] = {
        AddressData: {
            PublicKeyNew: convertPublicKeyToBackendFormat(data.pubXHex, data.pubYHex),
            Type: data.type,
            SeedAnchor:    hexEncode(data.seedAnchor),    // [NEW]
            SeedChainStep: data.seedChainStep,             // [NEW]
        }
    };
}
```

### 5.7 构造与发送普通交易（TXType=0）

> 这是整个改造的核心部分。

#### 5.7.1 交易构造完整流程

```go
func (a *Account) BuildNewTX(bills []BillMsg, feeRate float64) (*core.Transaction, error) {
    // ============================================
    // 第一步：按 Sweep 策略收集 UTXO
    //   每个地址只取最高步骤号的全部 UTXO
    // ============================================
    
    type addressSweep struct {
        step     int
        utxos    []core.UTXOData
        utxoIDs  []string
        totalVal float64
    }
    sweepMap := make(map[string]*addressSweep)

    for addr, addrData := range a.Wallet.AddressMsg {
        if len(addrData.UTXO) == 0 {
            continue
        }
        // 找出该地址最高步骤号
        maxStep := -1
        for _, utxo := range addrData.UTXO {
            if utxo.Output.SeedChainStep > maxStep {
                maxStep = utxo.Output.SeedChainStep
            }
        }
        // 收集该步骤号的所有 UTXO（Sweep：必须全部消费）
        sweep := &addressSweep{step: maxStep}
        for utxoID, utxo := range addrData.UTXO {
            if utxo.Output.SeedChainStep == maxStep {
                sweep.utxos = append(sweep.utxos, utxo)
                sweep.utxoIDs = append(sweep.utxoIDs, utxoID)
                sweep.totalVal += utxo.Output.ToValue
            }
        }
        sweepMap[addr] = sweep
    }

    // ============================================
    // 第二步：选择地址，凑够转账金额
    // ============================================
    
    totalNeeded := sumBillValues(bills) + fee
    var selectedAddrs []string
    var totalSelected float64
    
    // 按余额排序，贪心选取
    sortedAddrs := sortByValue(sweepMap)
    for _, addr := range sortedAddrs {
        if totalSelected >= totalNeeded {
            break
        }
        selectedAddrs = append(selectedAddrs, addr)
        totalSelected += sweepMap[addr].totalVal
    }
    
    if totalSelected < totalNeeded {
        return nil, fmt.Errorf("余额不足")
    }

    // ============================================
    // 第三步：为每个选中地址构造 TXInput
    // ============================================
    
    var inputs []core.TXInputNormal
    
    for _, addr := range selectedAddrs {
        addrData := a.Wallet.AddressMsg[addr]
        sweep := sweepMap[addr]
        
        // 取当前步骤的 seed 作为 revealSeed
        revealSeed := addrData.getSeedAtStep(sweep.step)
        
        // 派生一次性密钥
        oneTimeKP, _ := walletcrypto.DeriveKeyPairFromSeed("ecdsa_p256", revealSeed)
        
        // 为该地址的每一个 UTXO 创建 TXInput（Sweep：全部消费）
        for _, utxo := range sweep.utxos {
            outputHash := utxo.Output.GetTXOutputHash()
            sig, _ := walletcrypto.SignMessage("ecdsa_p256", oneTimeKP.PrivateKey, outputHash)
            
            input := core.TXInputNormal{
                FromAddress:    addr,
                FromTXID:       utxo.TXID,
                FromIndex:      utxo.Index,
                InputSignature: core.ConvertToEcdsaSignature(sig),
                SeedReveal:     revealSeed,
                SeedPublicKey:  core.ConvertToPublicKeyNew(oneTimeKP.PublicKey, "P256"),
                SeedChainStep:  sweep.step,
            }
            inputs = append(inputs, input)
        }
    }

    // ============================================
    // 第四步：构造 TXOutput（转账 + 找零）
    // ============================================
    
    var outputs []core.TXOutput
    
    // 4a. 转账输出（给接收方）
    for _, bill := range bills {
        output := core.TXOutput{
            ToAddress:     bill.ToAddress,
            ToValue:       bill.Value,
            ToGuarGroupID: bill.GuarGroupID,
            ToPublicKey:   bill.PublicKeyNew,       // 接收方地址公钥
            ToInterest:    bill.ToInterest,
            SeedAnchor:    bill.SeedAnchor,          // 接收方的 anchor
            SeedChainStep: bill.SeedChainStep,       // 接收方的步骤号
        }
        outputs = append(outputs, output)
    }
    
    // 4b. 找零输出（回到第一个被选中地址）
    changeAddr := selectedAddrs[0]
    changeAddrData := a.Wallet.AddressMsg[changeAddr]
    changeSweep := sweepMap[changeAddr]
    changeAmount := totalSelected - totalNeeded
    
    if changeAmount > 0 {
        nextStep := changeSweep.step - 1
        if nextStep < 0 {
            return nil, fmt.Errorf("地址 %s 的 seed 链已耗尽，请先续链", changeAddr)
        }
        nextSeed := changeAddrData.getSeedAtStep(nextStep)
        nextAnchor := walletcrypto.HashData("sha256", nextSeed)
        
        changeOutput := core.TXOutput{
            ToAddress:     changeAddr,
            ToValue:       changeAmount,
            ToGuarGroupID: a.GuarantorGroupID,
            ToPublicKey:   core.ConvertToPublicKeyNew(changeAddrData.WPublicKey, "P256"),
            SeedAnchor:    nextAnchor,
            SeedChainStep: nextStep,
        }
        outputs = append(outputs, changeOutput)
    }

    // ============================================
    // 第五步：本地更新步骤号
    // ============================================
    
    for _, addr := range selectedAddrs {
        addrData := a.Wallet.AddressMsg[addr]
        addrData.CurrentStep = sweepMap[addr].step - 1
        a.Wallet.AddressMsg[addr] = addrData
    }

    // ============================================
    // 第六步：TX 用户签名（AccountPrivateKey — 身份授权）
    //   注意：这是账户级签名，不是 Seed 链签名！
    //   与 InputSignature（Seed 链一次性密钥）形成双层安全
    // ============================================
    
    tx := &core.Transaction{
        TXInputsNormal: inputs,
        TXOutputs:      outputs,
    }
    userSig, err := tx.GetTXUserSignature(a.AccountPrivateKey)
    if err != nil {
        return nil, fmt.Errorf("TX UserSignature failed: %v", err)
    }
    tx.UserSignature = userSig

    return tx, nil
}
```

#### 5.7.2 BillMsg 结构改造

```go
type BillMsg struct {
    ToAddress     string             // 接收方地址
    MoneyType     int                // 货币类型
    Value         float64            // 金额
    GuarGroupID   string             // 担保组织 ID
    PublicKeyNew  core.PublicKeyNew  // [CHANGED] 接收方地址公钥
    ToInterest    float64            // 利息
    SeedAnchor    []byte             // [NEW] 接收方 anchor
    SeedChainStep int                // [NEW] 接收方步骤号
}
```

发送方构造 BillMsg 时需要查询接收方 anchor（见 5.11）。

#### 5.7.3 交易确认锁

```go
// 钱包必须实现交易确认锁：上一笔 TX 在链上确认前禁止构造下一笔
// 原因：同一 seed 不能签两笔不同的 TX

type TxLock struct {
    mu      sync.Mutex
    pending map[string]bool  // address → 是否有待确认 TX
}

func (l *TxLock) Acquire(addresses []string) error {
    l.mu.Lock()
    defer l.mu.Unlock()
    for _, addr := range addresses {
        if l.pending[addr] {
            return fmt.Errorf("address %s has pending TX, wait for confirmation", addr)
        }
    }
    for _, addr := range addresses {
        l.pending[addr] = true
    }
    return nil
}

func (l *TxLock) Release(addresses []string) {
    l.mu.Lock()
    defer l.mu.Unlock()
    for _, addr := range addresses {
        delete(l.pending, addr)
    }
}
```

### 5.8 UTXO 所有权验证（GuarNode 端）

#### 5.8.1 VerifyUTXOSig 完整替换

```go
// GuarNode/guarantor.go — 完全替换现有的 VerifyUTXOSig
func VerifyUTXOSig(utxo core.UTXOData, input core.TXInputNormal) error {
    output := utxo.Output

    // ===== 步骤 1：地址匹配 =====
    if input.FromAddress != output.ToAddress {
        return fmt.Errorf("address mismatch: input=%s, output=%s",
            input.FromAddress, output.ToAddress)
    }

    // ===== 步骤 2：哈希链承诺验证 =====
    computedAnchor := walletcrypto.HashData("sha256", input.SeedReveal)
    if !bytes.Equal(computedAnchor, output.SeedAnchor) {
        return fmt.Errorf("anchor mismatch: SHA256(SeedReveal) != UTXO.SeedAnchor")
    }

    // ===== 步骤 3：步骤号一致 =====
    if input.SeedChainStep != output.SeedChainStep {
        return fmt.Errorf("step mismatch: input=%d, output=%d",
            input.SeedChainStep, output.SeedChainStep)
    }

    // ===== 步骤 4：公钥与 seed 绑定 =====
    expectedKP, err := walletcrypto.DeriveKeyPairFromSeed("ecdsa_p256", input.SeedReveal)
    if err != nil {
        return fmt.Errorf("derive keypair failed: %v", err)
    }
    expectedPK := core.ConvertToPublicKeyNew(expectedKP.PublicKey, "P256")
    if !core.Equal(expectedPK, input.SeedPublicKey) {
        return fmt.Errorf("pubkey mismatch: derived != input.SeedPublicKey")
    }

    // ===== 步骤 5：签名验证 =====
    outputHash := output.GetTXOutputHash()
    ok, err := walletcrypto.VerifyMessage("ecdsa_p256", expectedKP.PublicKey,
        outputHash, core.ConvertFromEcdsaSignature(input.InputSignature))
    if err != nil || !ok {
        return fmt.Errorf("signature verification failed")
    }

    return nil
}
```

#### 5.8.2 VerifyTX 整体改造

```go
func (g *GuarNode) VerifyTX(tx core.Transaction) error {
    // ===== 0. 验证 TX.UserSignature（AccountPublicKey — 身份授权） =====
    // [CHANGED v5.1] 改用账户公钥验证，不再用地址公钥
    userID := g.getUserIDFromTX(tx) // 从 TXInput 地址反查 userID
    accountPK := g.LocalMsg.UserMsg.UserInfo[userID].AccountPublicKey
    err := tx.VerifyTXUserSignature(core.ConvertToPublicKey(accountPK))
    if err != nil {
        return fmt.Errorf("TX UserSignature verification failed: %v", err)
    }

    // ===== 1. 验证所有 TXInputNormal（Seed 链一次性密钥） =====
    for _, input := range tx.TXInputsNormal {
        utxo, err := g.findUTXO(input.FromAddress, input.FromTXID, input.FromIndex)
        if err != nil {
            return err
        }
        // RevokedAddresses 检查（现有逻辑不变）
        if g.isRevoked(input.FromAddress) {
            return fmt.Errorf("address %s is revoked", input.FromAddress)
        }
        // 分流：IsGuarMake 用组织密钥，其余用 seed 链
        if utxo.Output.IsGuarMake && len(utxo.Output.SeedAnchor) == 0 {
            err = VerifyGuarMakeSig(utxo, input)
        } else {
            err = VerifyUTXOSig(utxo, input)
        }
        if err != nil {
            return err
        }
    }

    // ===== 2. Sweep 检查：同地址同步骤的 UTXO 必须全部被消费 =====
    addrSteps := collectAddressSteps(tx.TXInputsNormal)
    for addr, step := range addrSteps {
        allUTXOs := g.getUTXOsByAddressAndStep(addr, step)
        consumed := countInputsByAddressAndStep(tx.TXInputsNormal, addr, step)
        if consumed != len(allUTXOs) {
            return fmt.Errorf("sweep violation: address %s step %d has %d UTXOs but only %d consumed",
                addr, step, len(allUTXOs), consumed)
        }
    }

    // ===== 3. TXCer 签名验证（见 5.9） =====
    for _, txcer := range tx.TXInputsCertificate {
        if err := VerifyTXCerSig(tx, txcer, accountPK); err != nil {
            return err
        }
    }

    // ===== 4. 金额平衡验证（现有逻辑不变） =====
    // ...

    return nil
}
```

**v5.1 关键变更：**
- 步骤 0 新增：TX.UserSignature 改用 `AccountPublicKey` 验证（原来用 `SubAddressMsg[addr].PublicKeyNew`）
- 步骤 1 不变：InputSignature 仍通过 Seed 链验证（VerifyUTXOSig）
- 步骤 3 变更：TXCer 验证也使用 AccountPublicKey（见 5.9.3）
- **双层安全**：步骤 0 验证账户授权 + 步骤 1 验证 UTXO 所有权
```

### 5.9 TXCer 即时凭证完整流程

#### 5.9.1 TXCer 创建（AggretionNode 端 — 不涉及 seed 链）

```
AggretionNode 确认用户 TX 后，为每个 TXOutput 创建 TXCer：

TxCertificate {
    TXCerID:            唯一ID,
    ToAddress:          接收方地址,
    ToGuarGroupID:      组织ID,
    Value:              金额,
    GuarGroupSignature: AggretionNode 组织私钥签名,
    UserSignature:      nil,   // 用户使用时用 AccountPrivateKey 签名
}
```

#### 5.9.2 TXCer 使用（用户端 — 在 BuildNewTX 中）

```go
// [CHANGED v5.1] TXCer 签名改用 AccountPrivateKey，不再使用 Seed 链
func (a *Account) signTXCers(txcerIDs []string) ([]core.TxCertificate, error) {
    var signedCerts []core.TxCertificate
    for _, id := range txcerIDs {
        txcer := a.Wallet.TotalTXCers[id]
        
        // 用账户私钥签名（身份授权，不是 UTXO 所有权证明）
        sig, _ := core.SignStruct(txcer, a.AccountPrivateKey,
            "GuarGroupSignature", "UserSignature")
        
        txcer.UserSignature = sig
        signedCerts = append(signedCerts, txcer)
    }
    return signedCerts, nil
}
```

**v5.1 变更说明：**
- 移除 `addr` 和 `step` 参数（不再依赖 Seed 链）
- 签名密钥从 `Seed 链一次性密钥` 改为 `a.AccountPrivateKey`
- 不再设置 `SeedReveal`、`SeedPublicKey`、`SeedChainStep`（这些字段已从 TxCertificate 移除）

#### 5.9.3 TXCer 验证（GuarNode 端）

```go
// [CHANGED v5.1] 传入 accountPK 用于验证 UserSignature
func VerifyTXCerSig(tx core.Transaction, txcer core.TxCertificate, accountPK core.PublicKeyNew) error {
    // 1. 验证组织签名（不变）
    aggPK := getAggretionNodePublicKey(txcer.ToGuarGroupID)
    if err := core.VerifyStructSig(txcer.GuarGroupSignature, aggPK, txcer,
        "GuarGroupSignature", "UserSignature"); err != nil {
        return fmt.Errorf("TXCer %s: org signature invalid", txcer.TXCerID)
    }

    // 2. [CHANGED v5.1] 验证用户签名（AccountPublicKey — 身份授权）
    if err := core.VerifyStructSig(txcer.UserSignature,
        core.ConvertToPublicKey(accountPK), txcer,
        "GuarGroupSignature", "UserSignature"); err != nil {
        return fmt.Errorf("TXCer %s: user signature invalid (AccountPublicKey)", txcer.TXCerID)
    }
    
    return nil
}
```

**v5.1 变更说明：**
- 移除全部 Seed 链验证逻辑（anchor、公钥派生、步骤号检查）
- UserSignature 改用 `AccountPublicKey` 验证
- 移除"同 TX 同地址同步骤"一致性检查（TXCer 签名不再绑定 Seed 链步骤）
- 函数签名新增 `accountPK` 参数（由 VerifyTX 传入，见 5.8.2）
```

### 5.10 区块处理与 StoragePoint 更新（GetStoragePoint）

> 基于 `core/block.go` GetStoragePoint() 的逐行分析。

#### 5.10.1 完整改造逻辑

```go
func (b *Block) GetStoragePoint() (StoragePoint, error) {
    Point := b.PreviousStoragePoint.DeepCopy()
    Height := b.Head.BlockHeight

    for _, subBlockBody := range b.Body.Transactions {
        for _, subATX := range subBlockBody.AggregateTX.AllTransactions {

            // ========== 处理 TXInput：删除已花费 UTXO ==========
            for _, input := range subATX.TXInputsNormal {
                addr := input.FromAddress
                subAddrMsg := Point.PointAddressMsg[addr]
                
                // 删除对应 UTXO（现有逻辑不变）
                utxoID := makeUTXOID(input.FromTXID, input.FromIndex)
                utxoData := subAddrMsg.UTXO[utxoID]
                subAddrMsg.Value -= utxoData.Output.ToValue
                delete(subAddrMsg.UTXO, utxoID)
                
                Point.PointAddressMsg[addr] = subAddrMsg
            }

            // ========== 处理 TXOutput：新增 UTXO ==========
            for indexZ, output := range subATX.TXOutputs {
                if output.IsPayForGas || output.IsCrossChain {
                    continue
                }

                subAddrMsg, isExist := Point.PointAddressMsg[output.ToAddress]
                utxoID := makeBlockUTXOID(Height, indexZ)

                if !isExist || subAddrMsg.PublicKeyNew == (PublicKeyNew{}) {
                    // ===== 新地址：完整初始化 =====
                    Point.PointAddressMsg[output.ToAddress] = PointAddressData{
                        PublicKeyNew:  output.ToPublicKey,
                        Value:         output.ToValue,
                        GroupID:       output.ToGuarGroupID,
                        Type:          output.Type,
                        Interest:      output.ToInterest,
                        LastHeight:    Height,
                        SeedAnchor:    output.SeedAnchor,
                        SeedChainStep: output.SeedChainStep,
                        UTXO: map[string]UTXOData{
                            utxoID: {Output: output},
                        },
                    }
                } else {
                    // ===== 已知地址 =====
                    // 公钥一致性检查（不变，但 IsGuarMake 的 output 可跳过）
                    if !output.IsGuarMake {
                        if err := core.Equal(output.ToPublicKey, subAddrMsg.PublicKeyNew); err != nil {
                            return StoragePoint{}, fmt.Errorf("pubkey mismatch for %s", output.ToAddress)
                        }
                    }
                    
                    // 添加 UTXO
                    subAddrMsg.UTXO[utxoID] = UTXOData{Output: output}
                    subAddrMsg.Value += output.ToValue
                    subAddrMsg.Interest += output.ToInterest
                    subAddrMsg.LastHeight = Height

                    // [KEY] 锚点更新规则：只有找零输出才更新地址级 anchor
                    if isChangeOutput(subATX, output) && len(output.SeedAnchor) > 0 {
                        subAddrMsg.SeedAnchor = output.SeedAnchor
                        subAddrMsg.SeedChainStep = output.SeedChainStep
                    }
                    
                    Point.PointAddressMsg[output.ToAddress] = subAddrMsg
                }
            }
        }
    }
    return Point, nil
}

// isChangeOutput 判断是否为找零输出（输入地址 == 输出地址）
func isChangeOutput(atx AggregateTX, output TXOutput) bool {
    for _, input := range atx.TXInputsNormal {
        if input.FromAddress == output.ToAddress {
            return true
        }
    }
    return false
}
```

#### 5.10.2 锚点更新规则总结

| 场景 | StoragePoint.SeedAnchor 更新？ | 说明 |
|------|-------------------------------|------|
| 新地址首次出现 | ✅ 从 TXOutput 初始化 | 地址从未在链上出现 |
| 已知地址收到转账 | ❌ 不更新 | UTXO 自身有 anchor，但不改地址级 |
| 已知地址的找零输出 | ✅ 更新为找零的 anchor | 反映消费后的新状态 |
| IsGuarMake 输出 | ❌ 不更新 | 组织管理的 UTXO 不影响用户 anchor |

### 5.11 发送方获取接收方地址信息

#### 5.11.1 信息来源优先级

| 优先级 | 来源 | 适用场景 | 可靠性 |
|-------|------|---------|-------|
| 1 | StoragePoint 查询（AssignNode API） | 同组织内转账 | 最可靠 |
| 2 | 链上 UTXO 最高步骤号的 anchor | 跨组织转账 | 可靠（但可能有延迟） |
| 3 | 接收方提供的收款码 | 新地址首次收款 | 需验证 |

#### 5.11.2 新增 API 端点

```go
// GET /api/v1/{groupID}/assign/address-info/{address}
type AddressInfoResponse struct {
    Address       string       `json:"address"`
    PublicKeyNew  PublicKeyNew `json:"publicKeyNew"`
    SeedAnchor    string       `json:"seedAnchor"`     // hex 编码
    SeedChainStep int          `json:"seedChainStep"`
    GroupID       string       `json:"groupID"`
}

// POST /api/v1/{groupID}/assign/address-anchor-batch
type BatchAnchorRequest struct {
    Addresses []string `json:"addresses"`
}
type BatchAnchorResponse struct {
    Anchors map[string]AddressInfoResponse `json:"anchors"`
}
```

#### 5.11.3 过期锚点与自动归集

```
场景：发送方用了接收方的旧 anchor（接收方在查询后消费了一笔）

  ① S 查到 R 的 anchor = SHA256(seed[100])，step=100
  ② R 花了一笔（暴露 seed[100]），step 变为 99
  ③ S 的 TX 上链 → 新 UTXO 锁在 step=100

风险：seed[100] 已公开，攻击者可以花这个 UTXO

对策：
  1. R 的钱包检测到 step=100 有新 UTXO → 自动发起归集 TX
  2. 归集 TX：用 seed[100] 解锁旧 UTXO → 转到 step=98 的 anchor
  3. 担保系统中 GuarNode 优先处理地址所有者的交易，竞争风险极低
  4. 根本对策：发送方尽量查最新 anchor
```

### 5.12 特殊交易类型处理

#### 5.12.1 质押交易（TXType=-1）

```
TXInput：用户的 seed 链签名（正常流程）
TXOutput（目标 = 质押地址）：
  ToAddress   = AggretionNode 质押地址
  IsGuarMake  = true
  ToPublicKey = AggretionNode.AggrPublicKeyNew
  SeedAnchor  = nil    ← 质押地址不使用 seed 链
  SeedChainStep = 0
```

#### 5.12.2 退押交易（TXType=5）

```
TXInput（花费质押 UTXO）：
  IsGuarMake → 用 AggretionNode 组织私钥签名
  SeedReveal = nil, SeedPublicKey = nil, SeedChainStep = 0
TXOutput（退回用户）：
  SeedAnchor    = StoragePoint[用户地址].SeedAnchor
  SeedChainStep = StoragePoint[用户地址].SeedChainStep
  ToPublicKey   = 用户地址公钥
```

#### 5.12.3 利息发放（TXType=4）

```
系统从组织资金池发放利息到用户地址：
TXOutput：
  ToAddress   = 用户地址
  IsGuarMake  = true     ← 由组织创建
  SeedAnchor  = StoragePoint[用户地址].SeedAnchor
  SeedChainStep = StoragePoint[用户地址].SeedChainStep

用户花费利息 UTXO 时：
  该 UTXO 有 SeedAnchor（非 nil）→ 走 seed 链验证
  与普通 UTXO 花费方式完全相同
```

#### 5.12.4 担保修改（TXType=2）/ 跨链（TXType=6/7）/ 散户（TXType=8）

```
担保修改（TXType=2）：
  TXInput: AggretionNode 组织密钥签名
  TXOutput: 给用户地址 → 填入用户 SeedAnchor/SeedChainStep

跨链转出（TXType=6）：
  TXInput: 用户 seed 链签名
  TXOutput: IsCrossChain=true → 跨链桥地址

跨链转入（TXType=7）：
  TXInput: 跨链桥签名
  TXOutput: 给用户地址 → 填入用户 SeedAnchor/SeedChainStep

散户交易（TXType=8）：
  TXInput: 用户 seed 链签名
  TXOutput: 给接收方 → 需通过收款码获取其 anchor
  注意：接收方可能不在任何组织，anchor 来自收款码或链上数据
```

### 5.13 地址管理：新建子地址、解绑、恢复

#### 5.13.1 新建子地址

完整流程见 5.5。要点：
- 独立 masterSeed，独立 seed 链
- 通知 AssignNode 携带 SeedAnchor / SeedChainStep
- AssignNode → ComNode 广播 `UserNewAddressNotify` 时也携带 anchor 字段

#### 5.13.2 地址解绑（Unbind）

```
解绑只改变组织归属，seed 链状态不受影响：
  - StoragePoint 中 anchor 信息保留（地址可能还有链上 UTXO）
  - 用户本地 masterSeed 随地址数据保留
  - RevokedAddresses 记录不需要 seed 链字段
```

#### 5.13.3 地址恢复（Rebind）

```go
func (a *AssignNode) rebindAddress(msg core.UserAddressBindingMsg) error {
    // 现有验证：GenerateAddress(PublicKey) == Address，签名校验
    
    // anchor 恢复：以链上数据为准
    sp := a.MasterBlockchain.LatestStoragePoint()
    if point, ok := sp.PointAddressMsg[msg.Address]; ok && len(point.SeedAnchor) > 0 {
        // StoragePoint 有数据 → 以链上为准
        addrData.SeedAnchor    = point.SeedAnchor
        addrData.SeedChainStep = point.SeedChainStep
    } else if len(msg.SeedAnchor) > 0 {
        // 链上无数据 → 从用户请求获取
        addrData.SeedAnchor    = msg.SeedAnchor
        addrData.SeedChainStep = msg.SeedChainStep
    }
}
```

### 5.14 Seed 链耗尽与续链

#### 5.14.1 链耗尽检测

```go
// 钱包在 BuildNewTX 中检测
if addrData.CurrentStep <= 10 {
    // 警告用户：seed 链即将耗尽，剩余 10 步
    notifyUser("seed 链剩余步骤不足，请尽快续链或转移资产")
}
if addrData.CurrentStep <= 0 {
    return nil, fmt.Errorf("seed 链已耗尽，无法构造交易")
}
```

#### 5.14.2 续链方案

**方案 A：链上续链交易（推荐，需协议支持）**

```
1. 用旧链最后一个可用步骤消费所有 UTXO
2. 在同一 TX 中包含续链证明：
   TXInput 特殊字段：
     IsChainRenew: true
     NewAnchor:    新链的 SHA256(newSeed[M])
     NewChainStep: M
     RenewSig:     用 AccountPrivateKey 签名(NewAnchor, NewChainStep)（身份授权）
3. 找零输出使用新链的 anchor

验证端：
  - 验证旧链的 SeedReveal（正常 anchor check）
  - 验证 RenewSig（确认续链是地址所有者发起的）
  - 接受新 anchor
```

**方案 B：换新地址（简单实用，推荐初期使用）**

```
1. 当 CurrentStep < 阈值（如 100），提示用户
2. 生成全新地址（新 masterSeed + 新 seed 链）
3. 把旧地址资产全部转到新地址
4. 在组织内注册新地址、注销旧地址
```

**实施建议：** 初期使用方案 B，后续版本实现方案 A。

### 5.15 前端改造清单

#### 5.15.1 TransferAreaInterface 改动

| 文件 | 改动内容 |
|------|---------|
| `backend/Account.go` | AddressData 新增 MasterSeed, ChainLength, CurrentStep, SeedCache |
| `backend/NewAccount.go` | 新建地址时生成 masterSeed + seed 链（调用 walletcrypto） |
| `backend/SendTX.go` — BillMsg | 新增 SeedAnchor, SeedChainStep |
| `backend/SendTX.go` — BuildNewTX | Sweep 选 UTXO + seed 链签名 + 找零 anchor |
| `backend/JoinGroup.go` | FlowApply 携带 anchor |
| `backend/GetAddressMsg.go` | 新增查询接收方 anchor 的 API 调用 |
| `js/services/transfer.ts` | 发送前查询接收方 anchor |
| `js/services/txBuilder.ts` | TXInput/TXOutput 序列化新增字段 |
| `js/services/group.ts` | 加入组织传 anchor |
| `js/services/wallet.ts` | 本地加密存储 masterSeed |

#### 5.15.2 PanguPayExtension 改动

| 文件 | 改动内容 |
|------|---------|
| `src/core/address.ts` | seed 链生成、DeriveKeyPairFromSeed |
| `src/core/signature.ts` | 一次性密钥签名 |
| `src/core/txBuilder.ts` | TXInput/TXOutput 新字段 + Sweep 逻辑 |
| `src/core/transfer.ts` | 查询接收方 anchor API |
| `src/core/group.ts` | 加入组织传 anchor |
| `src/core/storage.ts` | 加密存储 masterSeed |
| `src/core/accountPolling.ts` | 自动归集：检测旧步骤 UTXO 并发起归集 TX |

#### 5.15.3 新增 API

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/v1/{group}/assign/address-info/{addr}` | GET | 查询地址 anchor |
| `/api/v1/{group}/assign/address-anchor-batch` | POST | 批量查询 anchor |

### 5.16 完整改动文件清单与实施顺序

```
═══════════════════════════════════════════════════════════════
  Phase 0：密码库支持（CryptoArea）
═══════════════════════════════════════════════════════════════

CryptoArea/crypto/walletcrypto/
  └── 新增 DeriveKeyPairFromSeed(algorithm, seed) 函数
  └── 确保 RandomBytes, HashData, SignMessage, VerifyMessage 完备

═══════════════════════════════════════════════════════════════
  Phase 1A：核心数据结构改造（UTXO-Area/core/）
═══════════════════════════════════════════════════════════════

transaction.go
  ├── TXInputNormal  +SeedReveal, +SeedPublicKey, +SeedChainStep
  ├── TXOutput       +SeedAnchor, +SeedChainStep
  └── TxCertificate  UserSignature 改用 AccountPrivateKey（移除 SeedReveal/SeedPublicKey/SeedChainStep）

storagepoint.go
  └── PointAddressData  +SeedAnchor, +SeedChainStep

guargroup.go
  ├── UserNewAddressInfo    +SeedAnchor, +SeedChainStep
  ├── UserNewAddressNotify  +SeedAnchor, +SeedChainStep
  └── NodeMsg               +SeedAnchor, +SeedChainStep

guaruserinfo.go
  └── AddressData  +SeedAnchor, +SeedChainStep

address_binding.go
  └── UserAddressBindingMsg  +SeedAnchor, +SeedChainStep

═══════════════════════════════════════════════════════════════
  Phase 1B：钱包层改造（UTXO-Area/wallet/）
═══════════════════════════════════════════════════════════════

account.go
  └── AddressData  +MasterSeed, +ChainLength, +CurrentStep, +SeedCache

user.go
  ├── NewSubAddress()  → masterSeed + seed 链生成
  ├── BuildNewTX()     → Sweep + seed 签名 + anchor 找零 + TX.UserSignature(AccountPrivateKey)
  ├── signTXCers()     → TXCer UserSignature 改用 AccountPrivateKey
  └── JoinGroup()      → FlowApply 传 anchor

handle.go
  └── unbind/rebind 改造

═══════════════════════════════════════════════════════════════
  Phase 1C：节点验证改造（UTXO-Area/Guarantor/）
═══════════════════════════════════════════════════════════════

GuarNode/guarantor.go
  ├── VerifyUTXOSig()  → 完全替换为 seed 链 5 步验证
  ├── VerifyTX()       → +TX.UserSignature(AccountPublicKey) + Sweep 检查 + TXCer(AccountPublicKey)
  └── AddressToKey     → 保留（身份验证）

AssignNode/manage.go
  ├── ProcessUserFlowApply()   → 验证+存储 anchor
  └── ProcessUserNewAddress()  → 存储 anchor

AssignNode/address_binding.go
  └── rebindAddress()  → 恢复 anchor

AggretionNode/aggrnode.go
  ├── ProcessGuarTX()       → TXCer 创建（UserSignature 留空，用户用 AccountPrivateKey 签名）
  └── MakeGuarBlockchain()  → 利息/退押 TXOutput 填 anchor

═══════════════════════════════════════════════════════════════
  Phase 1D：出块与共识
═══════════════════════════════════════════════════════════════

core/block.go
  └── GetStoragePoint()  → anchor 传播与更新规则（见 5.10）

GuarCommittee/comnode.go
  └── VerifyNoGroupTX()  → seed 链验证

GuarCommittee/manage.go
  └── ProcessUserNewAddressNotify()  → 传递 anchor

═══════════════════════════════════════════════════════════════
  Phase 2：前端集成
═══════════════════════════════════════════════════════════════

TransferAreaInterface/
  ├── backend/*.go         → 与 wallet 层同步
  └── js/services/*.ts     → anchor 查询与传递

PanguPayExtension/
  └── src/core/*.ts         → 完整 seed 链前端支持

═══════════════════════════════════════════════════════════════
  Phase 3：测试与部署
═══════════════════════════════════════════════════════════════

测试矩阵：
  ✦ 单元测试：seed 链生成、DeriveKeyPairFromSeed、anchor 校验
  ✦ 集成测试：加入组织→转账→TXCer→利息→质押→退押 全流程
  ✦ Sweep 测试：多 UTXO 同步骤全扫验证
  ✦ 归集测试：过期 anchor UTXO 自动归集
  ✦ 边界测试：链耗尽、续链、地址解绑/恢复
  ✦ 性能测试：N=1000 链生成 < 5ms，签名验证 < 1ms
```


---

## 六、底层调用链路详解

### 6.1 签名调用链（以 ML-DSA 为例）

```
walletcrypto.SignMessage("pq_ml_dsa", sk, msg)
  └→ resolveAlgorithm("pq_ml_dsa")
      └→ Kind = algorithmKindPQC, PQCScheme = 2
  └→ pqcgo.Sign(2, msg, sk)                     // Go cgo 层
      └→ C.sign(2, sig, &siglen, m, mlen, sk)    // C 函数调用
          └→ pqcsign_wrapper.c: sign()
              └→ case ML_DSA:
                  pqmagic_ml_dsa_65_std_signature_internal(sig, siglen, m, mlen, coins, sk)
                      └→ libpqmagic.a (PQMagic C 静态库)
```

### 6.2 确定性密钥派生链路

```
walletcrypto.GenerateKeyPairWithSeed("pq_ml_dsa", seed)
  └→ pqcgo.KeyGenWithSeed(2, seed)
      └→ C.keyGenWithSeed(2, pk, sk, seed, seedLen)
          └→ pqcsign_wrapper.c: keyGenWithSeed()
              └→ derive_seed(内部seed, seed, seedLen)
                  └→ SHAKE256(seed) → 72字节内部种子
              └→ pqmagic_ml_dsa_65_std_keypair_internal(pk, sk, 内部种子)
```

**核心：** 任意长度的用户 seed 先通过 SHAKE256 扩展为固定 72 字节，再传给算法的确定性密钥生成函数。相同输入 → 相同输出。

---

## 七、编译与测试

### 7.1 环境要求

- Go 1.22.9+
- Windows: MinGW-w64（用于 cgo）
- Linux: gcc（用于 cgo）

### 7.2 无 cgo 测试（仅经典算法）

```powershell
cd crypto
$env:CGO_ENABLED="0"
go test ./walletcrypto/...
```

### 7.3 有 cgo 测试（包含后量子算法）

```powershell
cd crypto
$env:CGO_ENABLED="1"
go test ./walletcrypto/...
```

### 7.4 底层 pqcgo 测试

```powershell
cd pqcgo
$env:CGO_ENABLED="1"
go test ./...
```

### 7.5 性能基准测试

```powershell
cd pqcgo
$env:CGO_ENABLED="1"
go test -bench=. -benchtime=10s ./...
```

---

## 八、安全注意事项

### 8.1 核心安全规则

1. **masterSeed 是最高机密**：相当于传统意义上的"助记词"。哈希链和地址密钥均由它派生。丢失 masterSeed = 永久丢失资产。必须加密存储。
2. **masterSeed 永远不出现在交易中**：哈希链从 `seed[0] = SHA256(masterSeed)` 开始，即使链条全部消耗（暴露 seed[0]），也无法反推 masterSeed，地址私钥永远安全。
3. **seed 不可重用**：每个 seed 只能使用一次签名，用完必须递减 `currentStep`。重用同一个 seed 签名两笔不同交易等同于"签名泄露"。
4. **currentStep 必须持久化**：如果丢失当前步骤号，可通过扫描区块链恢复（见 4.9 问题六），但应尽量避免。
5. **PQC 依赖 cgo**：如果 `CGO_ENABLED=0`，所有 PQC 接口将返回错误。部署时务必确保 C 编译环境可用。
6. **签名体积较大**：切换到 ML-DSA 后签名 3,309 字节，远大于 ECDSA 的 64 字节，需考虑网络和存储开销。

### 8.2 哈希链方案特有的安全事项

7. **同步骤 UTXO 必须全额扫描（Sweep）**：如果只花掉同一步骤的部分 UTXO，剩余 UTXO 的 seed 已公开，资金可被窃取。钱包 `BuildNewTX` 已内置 Sweep 逻辑（见 5.7.1）。
8. **过期 anchor 是唯一的 seed 暴露风险来源**：发送方使用了接收方已消费步骤的旧 anchor → 新 UTXO 的 seed 已公开 → 需要接收方钱包自动归集（见 5.11.3）。
9. **用户不能同时构造两笔交易**：同一 seed 不能签两笔 TX，钱包需加锁（见 5.7.3 交易确认锁）。
10. **步骤号泄露交易计数**：`SeedChainStep` 暴露该地址消费次数，如有隐私需求可在未来版本加密（见 4.9 问题四）。
11. **续链交易初期使用方案 B（换新地址）**：方案 A 续链需要节点识别续链交易类型，初期可先用方案 B（见 5.14）。
12. **Seed 暴露后的竞争窗口**：seed 在 TX 广播后公开，理论上存在竞争风险。但在担保系统中，TX 直接发送到 GuarNode 处理，攻击者无法直接插入竞争交易，实际风险极低。

### 8.3 部署建议

13. **钱包层"交易确认锁"**：上一笔 TX 上链前禁止构造下一笔，防止 seed 重用（见 5.7.3）。
14. **自动归集守护进程**：钱包后台定期检查旧步骤号 UTXO，自动发起归集交易（见 5.11.3）。
15. **链长度推荐值**：普通用户 N=1000（够用 3-5 年），高频用户 N=10000。
16. **交易失败回滚**：交易超时未上链时，钱包应回滚 `currentStep`（seed 链是确定性的，回滚无风险）。
17. **首次收款引导**：新用户首次收款前，钱包应生成含 anchor 的收款码，或通过担保组织注册 anchor。

```

