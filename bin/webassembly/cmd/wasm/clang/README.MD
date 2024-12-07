# pqc clang转wasm

## 环境准备
1.  gcc
2.  cmake
3.  IDE推荐CLoin
4. 编译器使用Emscripten,参见 [官方文档](https://emscripten.org/docs/introducing_emscripten/index.html)

## 编译测试
> 需要执行两次编译,一个是编译pqmagic库,一个是编译pqcsign_wrapper.c
### 1.编译pqmagic库
- 切换到wasm分支
- 编译pqmagic库
```shell
cd  pqmagic && mkdir build && cd build
emmake  cmake -DCMAKE_INSTALL_PREFIX=../../libs -DUSE_SM3=OFF -DUSE_SHAKE=ON  -DENABLE_KYBER=OFF -DENABLE_ML_KEM=OFF  -DENABLE_AIGIS_ENC=OFF -DENABLE_TEST=OFF -DENABLE_BENCH=OFF ..
emmake  make &&  emmake  make install
```
编译完成后,在libs目录下会生成libpqmagic.a等库文件
### 2.编译pqcsign_wrapper.c
```shell
cd clang
./build.sh
```
### 3.在浏览器中测试
```shell
cd ../../server
go run main.go

```
打开浏览器,访问[http://localhost:9090/test_wrapper.html](http://localhost:9090/test_wrapper.html) 可以看到输出

```shell

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