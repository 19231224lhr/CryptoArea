# pqc clang转wasm

## 环境准备
1.  gcc
2.  cmake
3.  IDE推荐Goland

## 编译测试
> 需要执行两次编译,一个是编译pqmagic库,一个是编译pqcsign_wrapper.c
### 1.编译pqmagic库
- 切换到wasm分支
- 编译pqmagic库
```shell
cd  pqmagic && mkdir build && cd build
 cmake -DCMAKE_INSTALL_PREFIX=../../libs -DUSE_SM3=OFF -DUSE_SHAKE=ON  -DENABLE_KYBER=OFF -DENABLE_ML_KEM=OFF  -DENABLE_AIGIS_ENC=OFF -DENABLE_TEST=OFF -DENABLE_BENCH=OFF ..
 make &&  make install
```
编译完成后,在libs目录下会生成libpqmagic.a等库文件
### 2.编译pqcsign_wrapper.c
```shell
./build.sh
```
