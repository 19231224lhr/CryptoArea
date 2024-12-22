#!/bin/bash

echo "Compiling pqcsign_wrapper..."
emcc pqcsign_wrapper.c fips202.c  --emit-tsd=pqcsign.d.ts \
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
    -s EXPORTED_FUNCTIONS='["_keyGen", "_keyGenWithSeed", "_sign", "_verify", "_VerifyKeyGen", "_malloc", "_free"]' \
    -fsanitize=address \
    -s WASM=1 \
    -s ALLOW_MEMORY_GROWTH=1 \
    -s ASSERTIONS=1 \
    -o ./build/pqcsign.js \
    -s MODULARIZE=1 \
    -s EXPORT_NAME="createModule"

if [ $? -eq 0 ]; then
    echo "Compiling pqcsign_wrapper success!"
else
    echo "Compiling pqcsign_wrapper failed!"
fi

echo "Compiling testcase ..."

emcc test_wrapper.c pqcsign_wrapper.c fips202.c   --emit-tsd=testcase.d.ts \
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
    -s EXPORTED_FUNCTIONS='["_process_array", "_main", "_malloc", "_free"]' \
    -fsanitize=address \
    -s WASM=1 \
    -s ALLOW_MEMORY_GROWTH=1 \
    -s ASSERTIONS=1 \
    -o ./build/testcase.html

if [ $? -eq 0 ]; then
    echo "Compiling testcase success!"
else
    echo "Compiling testcase failed!"
fi

echo "Install binaries into assets directory..."
cp ./build/*  ../tests/assets/