#!/bin/bash

emcc pqcsign_wrapper.c -o ../../../assets/pqcsign_wrapper.js \
                -s EXPORTED_FUNCTIONS="['_test_add','_test_modify_array','_malloc', '_free']" \
                -s EXPORTED_RUNTIME_METHODS="['ccall', 'cwrap']" \
                -s -s ASSERTIONS=1

