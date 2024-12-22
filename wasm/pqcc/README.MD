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
