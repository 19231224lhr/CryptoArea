# pqc clang转wasm

## 环境准备
1.  gcc
2.  cmake
3.  IDE推荐CLoin
4. 编译器使用Emscripten,参见 [官方文档](https://emscripten.org/docs/introducing_emscripten/index.html)

## 测试编译
 ### 1. 测试PQMagic库
- 切换到linux分支
- 安装pqmagic依赖
```shell
cd  pqmagic && mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=../../libs -DUSE_SM3=OFF -DUSE_SHAKE=ON  -DENABLE_KYBER=OFF -DENABLE_ML_KEM=OFF  -DENABLE_AIGIS_ENC=OFF -DENABLE_TEST=OFF -DENABLE_BENCH=OFF ..
make && make install

```
- 回到主目录
```shell
 mkdir build && cd build
 cmake .. && make 
```
-  执行test_wrapper测试

### 2.编译到wasm库
- 切换到wasm分支
- 编译pqmagic库
```shell
cd  pqmagic && mkdir build && cd build
emcc cmake -DCMAKE_INSTALL_PREFIX=../../libs -DUSE_SM3=OFF -DUSE_SHAKE=ON  -DENABLE_KYBER=OFF -DENABLE_ML_KEM=OFF  -DENABLE_AIGIS_ENC=OFF -DENABLE_TEST=OFF -DENABLE_BENCH=OFF ..
emcc make && sudo emcc make install
```
- 
### 乱其八糟

#### 1. GPT提示词备份

在我的/usr/local/lib下存在以下文件:> tree -L 4
.
├── aigis-sig
│   ├── api.h
│   ├── config.h
│   └── params.h
├── dilithium
│   ├── api.h
│   ├── config.h
│   └── params.h
├── ml_dsa
│   ├── api.h
│   ├── config.h
│   └── params.h
└── slh_dsa
└── std
├── api.h
├── config.h
└── params.h
其中三个文件已经给出,请根据这些文件,帮我在pqc_sign.c中实现以下几个函数,封装这四个签名算法,封装函数的格式参考如下: keyGen: (scheme: SignAlgType) => Promise<{ sk: Buffer; pk: Buffer }> // 生成密钥对
keyGenWithSeed: (scheme: SignAlgType, seed: Buffer) => Promise<{ sk: Buffer; pk: Buffer }> // 根据前一个公钥的输入作为种子生成密钥对
sign: (scheme: SignAlgType, message: string, sk: Buffer) => Promise<string> // 签名
verify: (scheme: SignAlgType, message: string, signature: string, pk: Buffer) => Promise<boolean> // 验证签名
VerifyKeyGen(scheme: SignAlgType, fsk: Buffer, bsk: Buffer, bpk: string): Promise<boolean> // 验证前后密钥生成关系



![img.png](docs/img.png)