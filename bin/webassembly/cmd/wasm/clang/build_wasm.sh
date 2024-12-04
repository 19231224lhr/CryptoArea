#!/bin/bash

emcc pqc_sign.c -o ../../../assets/pqc_sign.js \
                -s EXPORTED_FUNCTIONS="['_test_add','_test_modify_array','_malloc', '_free']" \
                -s EXPORTED_RUNTIME_METHODS="['ccall', 'cwrap']" \
                -s -s ASSERTIONS=1

