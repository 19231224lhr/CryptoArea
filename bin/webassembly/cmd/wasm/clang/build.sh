#!/bin/bash

rm -rf ./build/*
mkdir -p build
cd build
emmake cmake ..
emmake make
cp pqcsign_wrapper.*  test_wrapper.*  ../../../../assets/

emcc pqcsign_wrapper.c -o ../../../assets/pqcsign_wrapper.js \
                -s EXPORTED_FUNCTIONS="['_test_add','_test_modify_array','_malloc', '_free']" \
                -s EXPORTED_RUNTIME_METHODS="['ccall', 'cwrap']" \
                -s  ASSERTIONS=1 \
                -s ENVIRONMENT=web


emcc pqcsign_wrapper.c fips202.c \
    -Ilibs/include \
    $(ls libs/lib/*.a libs/lib/*.so) \
    -DAIGIS_SIG_MODE=2 \
    -DDILITHIUM_MODE=3 \
    -DML_DSA_MODE=65 \
    -DSLH_DSA_MODE=\"slh-dsa-shake-192f\" \
    -O3 \
    -s EXPORTED_RUNTIME_METHODS='["ccall", "cwrap"]' \
    -s MODULARIZE=1 \
    -s ENVIRONMENT=web \
    -s EXPORT_NAME="createModule" \
    -s STACK_SIZE=131072 \
    -s EXPORTED_FUNCTIONS='["_keyGen", "_keyGenWithSeed", "_sign", "_verify", "_VerifyKeyGen", "_test_modify_array", "_test_add", "_malloc", "_free"]' \
    -fsanitize=address \
    -s WASM=1 \
    -s ALLOW_MEMORY_GROWTH=1 \
    -g SOURCE_MAP=1 \
    -s ASSERTIONS=1 \
    -o pqcsign_wrapper.js

emcc test_wrapper.c pqcsign_wrapper.c fips202.c \
    -Ilibs/include \
    libs/lib/libpqmagic.a \
    -DAIGIS_SIG_MODE=2 \
    -DDILITHIUM_MODE=3 \
    -DML_DSA_MODE=65 \
    -DSLH_DSA_MODE=\"slh-dsa-shake-192f\" \
    -O3 \
    -s EXPORTED_RUNTIME_METHODS='["ccall", "cwrap"]' \
    -s ENVIRONMENT=web \
    -s STACK_SIZE=131072 \
    -s EXPORTED_FUNCTIONS='["_test_add", "_process_array", "_main", "_malloc", "_free"]' \
    -fsanitize=address \
    -s WASM=1 \
    -s ALLOW_MEMORY_GROWTH=1 \
    -s ASSERTIONS=1 \
    -o test_wrapper.html
