#include <stdio.h>
#include <stdint.h>

void test_modify_array(int32_t *arr, int length) {
    for (int i = 0; i < length; i++) {
        arr[i] *= 2;  // 将数组元素值乘以2
    }
}

int test_add(int a, int b) {
    return a + b;
}