# crypto-suites
钱包端密码库，编译成wasm测试


### 0. 环境准备
1. golang
-  安装golang
- 复制gowasm胶水代码到assets目录下(版本要对应)
```shell
cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" ~/go/bin/webassembly/assets/  
```

2. clang
安装Emscripten
```shell
git clone ...
```

### 1. 编译wasm

1. 编译golang传统密码库
```shell
cd bin/webassembly/cmd/wasm/golang
 ./build.sh
```
在assets目录下生成了crypto.wasm文件
2. 编译c后量子密码库
```shell
cd bin/webassembly/cmd/wasm/clang
 ./build.sh
```
在assets目录下生成了mldsa.wasm文件