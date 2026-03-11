# PQC-UTXO-Simulator：后量子哈希链 UTXO 区块链模拟项目

> 版本：v1.0 | 日期：2026-02-28

---

## 一、项目目标

构建一个**本地可运行的最小完整区块链**，模拟并验证"后量子哈希链一次一钥"方案在真实 UTXO 交易场景中的完整可行性。

**核心要证明的事情：**

1. 用户可以用 Seed0 生成地址，后续每笔交易使用不同的 Seed 派生不同的 PQ 密钥签名
2. 验证节点可以通过哈希链承诺机制正确验证每笔交易的合法性
3. 整个流程形成完整的闭环：开户 → 充值 → 转账 → 验证 → 上链 → 再次转账 → ...
4. 不引入担保组织等复杂概念，采用简洁的 UTXO 模型

---

## 二、项目总体架构

```
pqc-utxo-simulator/
├── go.mod                          ← 依赖 blockchain-crypto 和 teddycode/pqcgo
├── main.go                         ← 入口：运行完整模拟流程
├── core/                           ← 区块链核心数据结构
│   ├── transaction.go              ← 交易、TXInput、TXOutput
│   ├── block.go                    ← 区块、区块头
│   ├── blockchain.go               ← 区块链（链 + UTXO 集）
│   └── utxo.go                     ← UTXO 集管理
├── wallet/                         ← 钱包与 Seed 链管理
│   ├── account.go                  ← 账户（ECDSA 身份密钥）
│   ├── address.go                  ← 地址（Seed 链 + PQ 密钥管理）
│   └── seedchain.go                ← Seed 链生成、持久化、回退
├── node/                           ← 模拟节点（验证 + 出块）
│   ├── validator.go                ← 交易验证逻辑
│   └── miner.go                    ← 简易出块逻辑
├── simulate/                       ← 模拟场景脚本
│   ├── scenario_basic.go           ← 基础场景：开户 → 转账 → 验证
│   ├── scenario_multi_tx.go        ← 多笔连续交易场景
│   ├── scenario_multi_user.go      ← 多用户互相转账场景
│   └── scenario_attack.go          ← 攻击模拟：伪造签名、重放等
└── tests/                          ← 单元测试
    ├── seedchain_test.go
    ├── transaction_test.go
    ├── validator_test.go
    └── full_flow_test.go
```

### 模块依赖

```go
// go.mod
module pqc-utxo-simulator

go 1.22.9

replace blockchain-crypto => ../CryptoArea/crypto
replace teddycode/pqcgo => ../CryptoArea/pqcgo

require (
    blockchain-crypto v0.0.0
    teddycode/pqcgo v0.0.0
)
```

---

## 三、核心数据结构设计

### 3.1 交易结构

参照 UTXO-Area 的 `Transaction` 结构，精简去掉担保组织相关的字段，保留核心 UTXO 逻辑，并**增加后量子哈希链字段**。

```go
// core/transaction.go

// Transaction 交易
type Transaction struct {
    TXID      string    // 交易 ID（交易体哈希的 hex）
    Version   int       // 交易版本号
    TXType    int       // 交易类型：0=普通交易, 1=Coinbase
    Value     float64   // 总转账金额
    Fee       float64   // 交易手续费
    Timestamp uint64    // 交易时间戳

    Inputs  []TXInput   // 交易输入
    Outputs []TXOutput  // 交易输出
}

// TXInput 交易输入 —— 花费一个已有的 UTXO
type TXInput struct {
    // ===== 引用 =====
    FromTXID   string  // 引用的 UTXO 所在交易 ID
    OutputIndex int    // 引用的 UTXO 在该交易输出中的索引

    // ===== 后量子哈希链签名证明 =====
    PQPublicKey  []byte // 本次交易使用的一次性 PQ 公钥（1952 bytes for ML-DSA-65）
    PQSignature  []byte // 对交易体的 PQ 签名（3309 bytes for ML-DSA-65）
    PQSeedReveal []byte // 公开的当前 seed（32 bytes）
    PQChainStep  int    // 当前哈希链步骤号

    // ===== 地址归属证明 =====
    FromAddress string // 花费者地址（不变的，由 Seed0 派生）
}

// TXOutput 交易输出 —— 创建一个新的 UTXO
type TXOutput struct {
    // ===== 基础 =====
    ToAddress string  // 接收地址
    ToValue   float64 // 金额

    // ===== 后量子哈希链锁定 =====
    PQAnchor    []byte // 下一次花费时需要满足 SHA256(seed) == PQAnchor（32 bytes）
    PQChainStep int    // 当前哈希链步骤号
}
```

**与 UTXO-Area 结构的对应关系：**

| UTXO-Area 字段 | 模拟项目字段 | 变化说明 |
|---------------|------------|---------|
| `TXInputNormal.FromTXID` | `TXInput.FromTXID` | 保留 |
| `TXInputNormal.InputSignature` (ECDSA) | `TXInput.PQSignature` (PQ) | **替换为后量子签名** |
| `TXInputNormal.TXOutputHash` | 不需要 | 验证逻辑改为哈希链 |
| `TXOutput.ToAddress` | `TXOutput.ToAddress` | 保留 |
| `TXOutput.ToPublicKey` (ECDSA) | `TXOutput.PQAnchor` (32bytes) | **替换为哈希承诺** |
| 无 | `TXOutput.PQChainStep` | **新增** |
| 无 | `TXInput.PQSeedReveal` | **新增** |
| 无 | `TXInput.PQPublicKey` | **新增** |
| `TXInputNormal.FromTxPosition` | `TXInput.OutputIndex` | 简化 |

### 3.2 区块结构

```go
// core/block.go

// Block 区块
type Block struct {
    Header BlockHeader
    Body   BlockBody
}

// BlockHeader 区块头
type BlockHeader struct {
    Height        int    // 区块高度
    Timestamp     uint64 // 出块时间
    PrevBlockHash []byte // 前一区块哈希
    BlockHash     []byte // 本区块哈希
    MerkleRoot    []byte // 交易 Merkle 根
    TXCount       int    // 交易数量
}

// BlockBody 区块体
type BlockBody struct {
    Transactions []Transaction // 本区块包含的交易列表
}
```

### 3.3 区块链与 UTXO 集

```go
// core/blockchain.go

// Blockchain 区块链
type Blockchain struct {
    Blocks    []Block               // 所有区块
    UTXOSet   map[string]UTXOEntry  // 全局 UTXO 集：key = "txid:index"
}

// core/utxo.go

// UTXOEntry UTXO 集中的一条记录
type UTXOEntry struct {
    TxID        string  // 所在交易 ID
    OutputIndex int     // 输出索引
    Output      TXOutput // 完整的输出内容
    IsSpent     bool    // 是否已花费
}
```

### 3.4 钱包与 Seed 链

```go
// wallet/account.go

// Account 用户账户
type Account struct {
    AccountID        string // 用户身份标识
    ECDSAPublicKey   []byte // ECDSA 公钥（仅作身份标识，不用于地址）
    ECDSAPrivateKey  []byte // ECDSA 私钥
    Addresses        map[string]*Address // 地址集合：address string → Address
}

// wallet/address.go

// Address 一个钱包地址的完整状态
type Address struct {
    AddressString string          // 地址字符串（由 Seed0 的 PQ 公钥派生，不变）
    Algorithm     string          // PQ 签名算法名（如 "pq_ml_dsa"）
    SeedChain     *SeedChain      // Seed 链管理器
    AddressPubKey []byte          // 地址公钥（Seed0 派生的 PQ 公钥，不变）
}

// wallet/seedchain.go

// SeedChain 哈希链 Seed 管理
type SeedChain struct {
    Seed0       []byte   // 根种子
    ChainLength int      // 链总长度 N
    CurrentStep int      // 当前步骤号（从 N 开始递减）
    Seeds       [][]byte // 完整的 seed 数组 [seed0, seed1, ..., seedN]

    // 缓存当前签名密钥（可选优化，避免重复派生）
    CurrentPQPublicKey  []byte
    CurrentPQPrivateKey []byte
}
```

---

## 四、核心逻辑设计

### 4.1 Seed 链初始化

```go
// wallet/seedchain.go

func NewSeedChain(chainLength int) (*SeedChain, error) {
    // 1. 生成 32 字节随机根种子
    seed0, err := walletcrypto.RandomBytes(32)

    // 2. 构建完整哈希链
    seeds := make([][]byte, chainLength+1)
    seeds[0] = seed0
    for i := 1; i <= chainLength; i++ {
        seeds[i], _ = walletcrypto.HashData("sha256", seeds[i-1])
    }

    // 3. 从 seed0 派生地址密钥
    addressKP, _ := walletcrypto.GenerateKeyPairWithSeed("pq_ml_dsa", seed0)

    // 4. 返回初始状态：currentStep = chainLength（从末端开始）
    return &SeedChain{
        Seed0:       seed0,
        ChainLength: chainLength,
        CurrentStep: chainLength,
        Seeds:       seeds,
    }, nil
}
```

### 4.2 从 Seed 链恢复

```go
// wallet/seedchain.go

func RecoverSeedChain(seed0 []byte, chainLength int, currentStep int) (*SeedChain, error) {
    // 1. 从 seed0 重建完整链
    seeds := make([][]byte, chainLength+1)
    seeds[0] = seed0
    for i := 1; i <= chainLength; i++ {
        seeds[i], _ = walletcrypto.HashData("sha256", seeds[i-1])
    }

    // 2. 恢复到指定步骤
    return &SeedChain{
        Seed0:       seed0,
        ChainLength: chainLength,
        CurrentStep: currentStep,
        Seeds:       seeds,
    }, nil
}
```

### 4.3 消费一次 Seed（签名用）

```go
// wallet/seedchain.go

// ConsumeSeed 消费当前 seed 用于签名，返回签名材料并前进一步
func (sc *SeedChain) ConsumeSeed() (seed []byte, pqPK []byte, pqSK []byte, step int, nextAnchor []byte, err error) {
    if sc.CurrentStep < 1 {
        return nil, nil, nil, 0, nil, errors.New("seed chain exhausted")
    }

    // 1. 取当前 seed
    currentSeed := sc.Seeds[sc.CurrentStep]
    currentStep := sc.CurrentStep

    // 2. 派生签名密钥
    kp, err := walletcrypto.GenerateKeyPairWithSeed("pq_ml_dsa", currentSeed)

    // 3. 计算下一步的 anchor（用于锁定找零 UTXO）
    nextStep := sc.CurrentStep - 1
    var anchor []byte
    if nextStep >= 1 {
        anchor, _ = walletcrypto.HashData("sha256", sc.Seeds[nextStep])
    }

    // 4. 递减步骤号
    sc.CurrentStep = nextStep

    return currentSeed, kp.PublicKey, kp.PrivateKey, currentStep, anchor, nil
}
```

### 4.4 构造交易

```go
// wallet/address.go

func (addr *Address) BuildTransaction(
    utxos []UTXOEntry,        // 要花费的 UTXO（从本地 UTXO 集选取）
    recipients []Recipient,    // 转账目标：[{address, amount}]
    fee float64,               // 手续费
) (*Transaction, error) {

    // 1. 计算总输入
    totalInput := sum(utxos)

    // 2. 计算总输出 + 手续费
    totalOutput := sum(recipients) + fee

    // 3. 计算找零
    change := totalInput - totalOutput

    // 4. 从 Seed 链消费一个 seed
    seed, pqPK, pqSK, step, nextAnchor, err := addr.SeedChain.ConsumeSeed()

    // 5. 构造 Outputs
    var outputs []TXOutput
    for _, r := range recipients {
        outputs = append(outputs, TXOutput{
            ToAddress:   r.Address,
            ToValue:     r.Amount,
            PQAnchor:    r.PQAnchor,     // 接收方地址的当前 anchor（接收方提供）
            PQChainStep: r.PQChainStep,  // 接收方的当前步骤号（接收方提供）
        })
    }
    // 找零 output（回到自己）
    if change > 0 {
        outputs = append(outputs, TXOutput{
            ToAddress:   addr.AddressString,
            ToValue:     change,
            PQAnchor:    nextAnchor,     // 自己的下一步 anchor
            PQChainStep: addr.SeedChain.CurrentStep,
        })
    }

    // 6. 构造交易体（先不含签名，用于计算哈希）
    tx := &Transaction{
        Version:   1,
        TXType:    0,
        Value:     sum(recipients),
        Fee:       fee,
        Timestamp: currentTimestamp(),
        Outputs:   outputs,
    }

    // 7. 构造 Inputs 并签名
    // 先序列化交易体获得待签名的 bytes
    txBytes := SerializeForSigning(tx)

    // 对每个输入用同一把密钥签名（因为是同一个地址的 UTXO）
    pqSig, err := walletcrypto.SignMessage("pq_ml_dsa", pqSK, txBytes)

    for _, utxo := range utxos {
        tx.Inputs = append(tx.Inputs, TXInput{
            FromTXID:     utxo.TxID,
            OutputIndex:  utxo.OutputIndex,
            PQPublicKey:  pqPK,
            PQSignature:  pqSig,
            PQSeedReveal: seed,
            PQChainStep:  step,
            FromAddress:  addr.AddressString,
        })
    }

    // 8. 计算 TXID
    tx.TXID = hex(SHA256(SerializeFull(tx)))

    return tx, nil
}
```

**重要设计说明：**

- 同一笔交易中，如果多个 Input 来自同一个地址，它们**共享同一个 seed 和签名**（同一步只消费一个 seed）
- 如果多个 Input 来自**不同地址**，每个地址各自消费自己的 seed（在多地址钱包场景中）

### 4.5 交易验证

```go
// node/validator.go

func ValidateTransaction(tx *Transaction, utxoSet map[string]UTXOEntry) error {

    // ===== 基本检查 =====
    if tx.TXType == 1 { // Coinbase
        return validateCoinbase(tx)
    }
    if len(tx.Inputs) == 0 {
        return errors.New("transaction has no inputs")
    }
    if len(tx.Outputs) == 0 {
        return errors.New("transaction has no outputs")
    }

    // ===== 逐个 Input 验证 =====
    totalInputValue := 0.0
    txBytesForVerify := SerializeForSigning(tx) // 去除签名字段后序列化

    // 按地址分组（同地址 input 共享一个 seed）
    inputsByAddress := groupInputsByAddress(tx.Inputs)

    for address, inputs := range inputsByAddress {
        // 取该地址组的第一个 input 的签名材料（同地址共享）
        representative := inputs[0]

        for _, input := range inputs {
            // ---- 验证 1: UTXO 存在且未花费 ----
            utxoKey := input.FromTXID + ":" + strconv.Itoa(input.OutputIndex)
            utxo, exists := utxoSet[utxoKey]
            if !exists || utxo.IsSpent {
                return fmt.Errorf("UTXO not found or already spent: %s", utxoKey)
            }

            // ---- 验证 2: 地址匹配 ----
            if utxo.Output.ToAddress != address {
                return fmt.Errorf("address mismatch: input claims %s, UTXO locked to %s",
                    address, utxo.Output.ToAddress)
            }

            // ---- 验证 3: 哈希链承诺 ----
            // SHA256(input.PQSeedReveal) == UTXO 中存的 PQAnchor
            expectedAnchor, _ := walletcrypto.HashData("sha256", representative.PQSeedReveal)
            if !bytes.Equal(expectedAnchor, utxo.Output.PQAnchor) {
                return fmt.Errorf("hash chain anchor mismatch for UTXO %s", utxoKey)
            }

            // ---- 验证 4: 步骤号一致 ----
            if representative.PQChainStep != utxo.Output.PQChainStep {
                return fmt.Errorf("chain step mismatch: input=%d, UTXO=%d",
                    representative.PQChainStep, utxo.Output.PQChainStep)
            }

            totalInputValue += utxo.Output.ToValue
        }

        // ---- 验证 5: PQ 公钥与 seed 绑定 ----
        expectedKP, _ := walletcrypto.GenerateKeyPairWithSeed("pq_ml_dsa", representative.PQSeedReveal)
        if !bytes.Equal(expectedKP.PublicKey, representative.PQPublicKey) {
            return fmt.Errorf("PQ public key does not match seed for address %s", address)
        }

        // ---- 验证 6: PQ 签名验证 ----
        ok, err := walletcrypto.VerifyMessage("pq_ml_dsa", representative.PQPublicKey,
            txBytesForVerify, representative.PQSignature)
        if err != nil || !ok {
            return fmt.Errorf("PQ signature verification failed for address %s", address)
        }
    }

    // ===== 金额平衡检查 =====
    totalOutputValue := 0.0
    for _, output := range tx.Outputs {
        if output.ToValue <= 0 {
            return errors.New("output value must be positive")
        }
        totalOutputValue += output.ToValue
    }
    if totalInputValue < totalOutputValue + tx.Fee {
        return fmt.Errorf("insufficient funds: input=%.2f, output+fee=%.2f",
            totalInputValue, totalOutputValue+tx.Fee)
    }

    return nil
}
```

### 4.6 UTXO 集更新

```go
// core/blockchain.go

func (bc *Blockchain) ApplyTransaction(tx *Transaction) {
    // 1. 标记已花费的 UTXO
    for _, input := range tx.Inputs {
        key := input.FromTXID + ":" + strconv.Itoa(input.OutputIndex)
        if entry, ok := bc.UTXOSet[key]; ok {
            entry.IsSpent = true
            bc.UTXOSet[key] = entry
        }
    }

    // 2. 添加新的 UTXO
    for i, output := range tx.Outputs {
        key := tx.TXID + ":" + strconv.Itoa(i)
        bc.UTXOSet[key] = UTXOEntry{
            TxID:        tx.TXID,
            OutputIndex: i,
            Output:      output,
            IsSpent:     false,
        }
    }
}
```

### 4.7 出块

```go
// node/miner.go

func (bc *Blockchain) MineBlock(txs []Transaction) (*Block, error) {
    prevBlock := bc.Blocks[len(bc.Blocks)-1]

    // 1. 验证所有交易
    for _, tx := range txs {
        if err := ValidateTransaction(&tx, bc.UTXOSet); err != nil {
            return nil, fmt.Errorf("invalid tx %s: %w", tx.TXID, err)
        }
    }

    // 2. 构造区块
    block := &Block{
        Header: BlockHeader{
            Height:        prevBlock.Header.Height + 1,
            Timestamp:     currentTimestamp(),
            PrevBlockHash: prevBlock.Header.BlockHash,
            TXCount:       len(txs),
            MerkleRoot:    computeMerkleRoot(txs),
        },
        Body: BlockBody{
            Transactions: txs,
        },
    }
    block.Header.BlockHash = computeBlockHash(block.Header)

    // 3. 应用所有交易到 UTXO 集
    for _, tx := range txs {
        bc.ApplyTransaction(&tx)
    }

    // 4. 上链
    bc.Blocks = append(bc.Blocks, *block)

    return block, nil
}
```

---

## 五、模拟流程设计

### 5.1 场景一：基础完整流程（单用户）

这是最核心的验证场景，证明完整流程可行。

```
步骤 1: 系统初始化
  ├── 创建创世区块（Genesis Block）
  └── 初始化空 UTXO 集

步骤 2: 用户 Alice 开户
  ├── 生成 ECDSA 身份密钥对（仅作标识）
  ├── 创建地址: 生成 Seed0 → 构建 1000 步哈希链
  ├── 从 Seed0 派生 PQ 公钥 → 生成 Base58Check 地址
  └── 显示: Alice 的地址、Seed 链状态

步骤 3: Coinbase 交易（给 Alice 充值）
  ├── 构造 Coinbase 交易: 100 个币 → Alice 的地址
  ├── TXOutput 设置:
  │   ├── ToAddress = Alice 的地址
  │   ├── PQAnchor = SHA256(seed[1000])
  │   └── PQChainStep = 1000
  ├── 打包进区块 #1
  └── UTXO 集更新: 新增 1 条 UTXO

步骤 4: Alice 发送第一笔交易（转给 Bob）
  ├── Bob 也执行开户流程（步骤 2）
  ├── Alice 构造交易:
  │   ├── Input: 引用 Coinbase 的 UTXO
  │   │   ├── 消费 seed[1000] → 派生 PQ 密钥
  │   │   ├── 用 PQ 私钥签名
  │   │   └── 公开 seed[1000]
  │   ├── Output 1: 30 币 → Bob 的地址（带 Bob 的 anchor）
  │   └── Output 2: 69 币 → Alice 的地址（找零，anchor = SHA256(seed[999])）
  │                  1 币手续费
  ├── 验证交易（完整的 6 步验证）
  ├── 打包进区块 #2
  └── UTXO 集更新:
      ├── 移除: Coinbase UTXO（已花费）
      ├── 新增: Bob 的 30 币 UTXO
      └── 新增: Alice 的 69 币找零 UTXO

步骤 5: Alice 发送第二笔交易
  ├── 这次从找零 UTXO 再转账
  ├── Input: 引用步骤 4 的找零 UTXO
  │   ├── 消费 seed[999] → 派生新的 PQ 密钥（和上次完全不同！）
  │   ├── 验证: SHA256(seed[999]) == 找零 UTXO 的 PQAnchor ✓
  │   └── 地址不变，但签名密钥全换了
  ├── Output: 20 币 → Bob, 48 币 → Alice 找零
  ├── 验证 + 上链
  └── Alice 的 currentStep 更新为 998

步骤 6: 验证 Seed 链连续性
  ├── 检查: 第 1 笔交易用了 seed[1000]
  ├── 检查: 第 2 笔交易用了 seed[999]
  ├── 验证: SHA256(seed[999]) == SHA256(seed[999])
  │   即第 2 笔的 seed 的哈希 == 第 1 笔找零 UTXO 的 anchor ✓
  └── 证明两笔交易确实来自同一个地址的合法持有人

步骤 7: 打印最终状态
  ├── 区块链: 3 个区块
  ├── Alice: 地址不变, currentStep=998, 余额 48 币
  ├── Bob: 余额 50 币
  └── 所有验证通过
```

### 5.2 场景二：多笔连续交易

验证同一个地址连续发送多笔交易时 Seed 链的正确递减。

```
Alice 连续发送 10 笔交易:
  TX #1: seed[1000] → 验证 anchor → 找零 anchor=SHA256(seed[999])
  TX #2: seed[999]  → 验证 anchor → 找零 anchor=SHA256(seed[998])
  TX #3: seed[998]  → 验证 anchor → 找零 anchor=SHA256(seed[997])
  ...
  TX #10: seed[991] → 验证 anchor → 找零 anchor=SHA256(seed[990])

验证：
  - 每笔交易的签名密钥都不同
  - 没有任何 seed 被重用
  - 所有 anchor 链路正确衔接
  - Alice 的地址始终不变
  - currentStep 从 1000 递减到 990
```

### 5.3 场景三：多用户交互

```
Alice, Bob, Charlie 三个用户各自开户:

Round 1:
  - Alice →(30)→ Bob        (Alice: seed[1000])
  - Bob   →(10)→ Charlie    (Bob:   seed[1000])

Round 2:
  - Charlie →(5)→ Alice     (Charlie: seed[1000])
  - Alice   →(20)→ Charlie  (Alice:   seed[999])
  - Bob     →(15)→ Alice    (Bob:     seed[999])

验证：
  - 每个用户独立维护自己的 Seed 链
  - 用户之间转账时，接收方提供自己地址当前的 anchor
  - 所有链上验证正确
```

### 5.4 场景四：安全攻击模拟

#### 攻击 A：伪造签名

```
  攻击者看到 Alice 的 seed[1000]（已公开），尝试:
  1. 从 seed[1000] 正向计算 seed[1001]（不可能，哈希单向）
  2. 反向猜测 seed[999]（不可能，哈希原像攻击）
  → 验证结果：攻击失败，anchor 不匹配
```

#### 攻击 B：重放攻击

```
  攻击者截获 Alice TX #1 的完整数据，尝试重放:
  1. 重新提交相同的交易
  → 验证结果：失败，因为 UTXO 已被标记为花费
```

#### 攻击 C：使用已泄露的旧 seed

```
  攻击者获得了 Alice 的 seed[1000]（第一笔交易公开的），尝试:
  1. 用 seed[1000] 派生密钥并签名
  2. 但当前 UTXO 的 anchor = SHA256(seed[999])
  3. SHA256(seed[1000]) ≠ SHA256(seed[999])
  → 验证结果：失败，anchor 不匹配
```

#### 攻击 D：伪造 seed

```
  攻击者构造一个假 seed_fake:
  1. 使 SHA256(seed_fake) == 当前 UTXO 的 PQAnchor
  → 这等价于找到 SHA256 的碰撞/原像，计算上不可行
  即使偶然找到：
  2. seed_fake 派生的 PQ 公钥 ≠ 攻击者控制的任何密钥
  → 无法产生有效的 PQ 签名
```

---

## 六、完整模拟入口 main.go 设计

```go
func main() {
    fmt.Println("========================================")
    fmt.Println("  PQC-UTXO Simulator v1.0")
    fmt.Println("  后量子哈希链一次一钥 UTXO 模拟器")
    fmt.Println("========================================")

    // ===== 1. 初始化区块链 =====
    bc := core.NewBlockchain() // 内含创世区块

    // ===== 2. 创建用户 =====
    alice := wallet.NewAccount("Alice", 1000, "pq_ml_dsa")
    bob   := wallet.NewAccount("Bob",   1000, "pq_ml_dsa")
    fmt.Printf("Alice 地址: %s (Seed链: %d步)\n", alice.DefaultAddress(), 1000)
    fmt.Printf("Bob   地址: %s (Seed链: %d步)\n", bob.DefaultAddress(), 1000)

    // ===== 3. Coinbase 给 Alice 充值 =====
    coinbaseTx := core.NewCoinbaseTransaction(alice.DefaultAddress(), 100.0,
        alice.DefaultAddr().CurrentAnchor(), alice.DefaultAddr().CurrentStep())
    bc.MineBlock([]Transaction{coinbaseTx})
    fmt.Println("✅ 区块 #1: Coinbase → Alice 100 币")

    // ===== 4. Alice → Bob 转账 =====
    tx1, _ := alice.BuildTx(bc, bob.DefaultAddress(), 30.0, 1.0,
        bob.DefaultAddr().CurrentAnchor(), bob.DefaultAddr().CurrentStep())
    bc.MineBlock([]Transaction{tx1})
    fmt.Println("✅ 区块 #2: Alice →(30)→ Bob")
    fmt.Printf("   Alice seed步骤: %d → %d\n", 1000, alice.DefaultAddr().CurrentStep())

    // ===== 5. Alice 再次转账 =====
    tx2, _ := alice.BuildTx(bc, bob.DefaultAddress(), 20.0, 1.0,
        bob.DefaultAddr().CurrentAnchor(), bob.DefaultAddr().CurrentStep())
    bc.MineBlock([]Transaction{tx2})
    fmt.Println("✅ 区块 #3: Alice →(20)→ Bob")
    fmt.Printf("   Alice seed步骤: %d\n", alice.DefaultAddr().CurrentStep())

    // ===== 6. Bob → Alice 转账 =====
    tx3, _ := bob.BuildTx(bc, alice.DefaultAddress(), 10.0, 1.0,
        alice.DefaultAddr().CurrentAnchor(), alice.DefaultAddr().CurrentStep())
    bc.MineBlock([]Transaction{tx3})
    fmt.Println("✅ 区块 #4: Bob →(10)→ Alice")

    // ===== 7. 打印最终状态 =====
    fmt.Println("\n======== 最终状态 ========")
    fmt.Printf("区块链高度: %d\n", bc.Height())
    fmt.Printf("Alice 余额: %.2f, Seed步骤: %d\n",
        bc.GetBalance(alice.DefaultAddress()), alice.DefaultAddr().CurrentStep())
    fmt.Printf("Bob   余额: %.2f, Seed步骤: %d\n",
        bc.GetBalance(bob.DefaultAddress()), bob.DefaultAddr().CurrentStep())

    // ===== 8. 安全测试 =====
    fmt.Println("\n======== 安全测试 ========")
    // 尝试用旧 seed 伪造交易...
    // 尝试重放攻击...
    // 结果应全部失败
}
```

---

## 七、测试计划

### 7.1 单元测试

| 测试文件 | 测试内容 | 关键验证点 |
|---------|---------|-----------|
| `seedchain_test.go` | Seed 链生成与恢复 | 同一 seed0 → 同一链；步骤递减正确 |
| `seedchain_test.go` | Seed 确定性派生 | 同 seed → 同密钥；不同 seed → 不同密钥 |
| `transaction_test.go` | 交易构造 | 字段正确、签名有效、TXID 正确 |
| `validator_test.go` | 验证逻辑 | 6 步验证全部通过 |
| `validator_test.go` | 拒绝无效交易 | 伪造签名失败、anchor 不匹配失败 |
| `full_flow_test.go` | 端到端完整流程 | 从开户到多次转账全通过 |

### 7.2 测试用例详细设计

#### Test 1: Seed 链确定性

```go
func TestSeedChainDeterministic(t *testing.T) {
    // 用同一个 seed0 生成两条链，应完全相同
    sc1 := NewSeedChainFromSeed(seed0, 100)
    sc2 := NewSeedChainFromSeed(seed0, 100)
    assert.Equal(t, sc1.Seeds, sc2.Seeds)

    // 从同一 seed 派生的密钥对应相同
    kp1, _ := walletcrypto.GenerateKeyPairWithSeed("pq_ml_dsa", sc1.Seeds[50])
    kp2, _ := walletcrypto.GenerateKeyPairWithSeed("pq_ml_dsa", sc2.Seeds[50])
    assert.Equal(t, kp1.PublicKey, kp2.PublicKey)
}
```

#### Test 2: Anchor 验证

```go
func TestAnchorVerification(t *testing.T) {
    sc := NewSeedChain(100)

    // seed[100] 应满足 SHA256(seed[100]) 等于什么？
    // 是的—— 如果 UTXO 中存的 anchor = SHA256(seed[100])
    // 那么亮出 seed[100] 后 SHA256(seed[100]) 应该等于 anchor

    anchor, _ := walletcrypto.HashData("sha256", sc.Seeds[100])
    check, _ := walletcrypto.HashData("sha256", sc.Seeds[100])
    assert.Equal(t, anchor, check)

    // 但 SHA256(seed[99]) ≠ anchor（不同的 seed）
    wrongCheck, _ := walletcrypto.HashData("sha256", sc.Seeds[99])
    assert.NotEqual(t, anchor, wrongCheck)
}
```

#### Test 3: 完整交易签名验证

```go
func TestFullTransactionSignAndVerify(t *testing.T) {
    // 1. Alice 开户
    alice := NewAccount("Alice", 100, "pq_ml_dsa")

    // 2. Coinbase
    bc := NewBlockchain()
    coinbase := NewCoinbase(alice, 100.0)
    bc.MineBlock([]Transaction{coinbase})

    // 3. 转账
    tx := alice.BuildTx(bc, someAddress, 30.0, 1.0, ...)

    // 4. 验证
    err := ValidateTransaction(tx, bc.UTXOSet)
    assert.NoError(t, err)
}
```

#### Test 4: 攻击模拟测试

```go
func TestRejectForgery(t *testing.T) {
    // 构造正常交易
    tx := buildValidTx(...)

    // 篡改签名
    tx.Inputs[0].PQSignature[0] ^= 0xFF
    err := ValidateTransaction(tx, utxoSet)
    assert.Error(t, err) // 应该拒绝

    // 使用旧 seed
    oldSeedTx := buildTxWithOldSeed(...)
    err = ValidateTransaction(oldSeedTx, utxoSet)
    assert.Error(t, err) // anchor 不匹配
}
```

### 7.3 运行测试

```powershell
cd pqc-utxo-simulator

# 运行全部测试
$env:CGO_ENABLED="1"
go test ./... -v

# 运行特定场景
go test -run TestFullFlow ./tests/ -v

# 运行基准测试（测量签名/验签性能）
go test -bench=. -benchtime=5s ./tests/
```

---

## 八、关键设计决策与讨论

### 8.1 为什么地址由 Seed0 决定

- Seed0 是哈希链的起点，只用于生成地址，**永远不用于签名**
- 这保证了即使后续所有签名 seed 都被公开，地址公钥（Seed0 派生的）仍然是安全的
- 地址 = Hash(PQ_PubKey_0)，是一个确定的、不变的标识

### 8.2 为什么不直接存 PQ 公钥

- ML-DSA-65 公钥 = 1,952 字节
- 每个 UTXO 如果存一个 PQ 公钥，链上数据膨胀约 30x（相比 ECDSA 的 33 字节）
- 改为存 32 字节的 anchor，链上开销极小
- 代价：每次花钱时多传 1,952 字节公钥 + 32 字节 seed，但这是一次性的

### 8.3 收到别人转账时 anchor 怎么来

当 Bob 要接收 Alice 的转账时：
- Bob 需要告诉 Alice 自己当前的 `PQAnchor` 和 `PQChainStep`
- 这可以在链下通信时完成（类似 Bitcoin 中你发送地址给对方）
- 或者可以让接收方的 anchor 信息公开可查（类似链上地址状态）

### 8.4 同一笔交易多个 Input 的处理

- 如果多个 Input 来自**同一个地址**，只消耗一个 seed，共享签名
- 如果来自**不同地址**，每个地址各消耗一个 seed
- 这避免了一笔交易白白浪费多个 seed

### 8.5 手续费处理

简化处理：`总输入 - 总输出 = 手续费`（类似 Bitcoin 模型），不单独构造 Fee Output。

---

## 九、后续扩展方向

| 方向 | 说明 |
|------|------|
| 集成到 UTXO-Area | 在现有 Transaction/TXInput/TXOutput 上增加 PQ 字段 |
| 网络模拟 | 加入 P2P 模拟，多节点共识 |
| Merkle 证明 | 实现完整的 Merkle Tree 和 SPV 验证 |
| Seed 链续签 | 实现哈希链用完后的续链协议 |
| 多算法支持 | 同时支持 ML-DSA + SLH-DSA 作为异构签名 |
| 性能优化 | Seed 链部分缓存、批量验证等 |
| 前端可视化 | Web 界面展示区块、交易、Seed 链状态 |
| Keystore 集成 | 完整的 Seed0 加密存储与恢复流程 |

---

## 十、项目启动检查清单

- [ ] 确认 CryptoArea 编译通过：`cd crypto && CGO_ENABLED=1 go test ./walletcrypto/...`
- [ ] 确认 pqcgo 编译通过：`cd pqcgo && CGO_ENABLED=1 go test ./...`
- [ ] 创建 `pqc-utxo-simulator` 项目目录
- [ ] 配置 `go.mod` 依赖（replace 本地路径）
- [ ] 实现 `core/` 数据结构
- [ ] 实现 `wallet/seedchain.go`
- [ ] 实现 `wallet/account.go` + `address.go`
- [ ] 实现 `node/validator.go`
- [ ] 实现 `node/miner.go`
- [ ] 实现 `simulate/scenario_basic.go`
- [ ] 编写并通过全部单元测试
- [ ] 运行完整模拟并输出结果
