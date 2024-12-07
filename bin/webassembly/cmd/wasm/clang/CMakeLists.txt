cmake_minimum_required(VERSION 3.10)

# 设置项目名称及使用的语言
project(PQC_Signature LANGUAGES C)

# 检查是否使用Emscripten的Clang编译器
if (CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(STATUS "使用 Emscripten 的 Clang 编译器")
else()
    message(FATAL_ERROR "该项目需要使用 Emscripten 的 Clang 编译器")
endif()

# 包含头文件目录
include_directories(libs/include)

# 启用编译命令导出
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# 定义源文件
set(SOURCES
        pqcsign_wrapper.c
        fips202.c
        test_wrapper.c
)

# 添加可执行目标
add_executable(pqcsign_wrapper pqcsign_wrapper.c fips202.c)
add_executable(test_wrapper test_wrapper.c pqcsign_wrapper.c fips202.c)

# 添加外部库
file(GLOB LIB_FILES "libs/lib/*.a" "libs/lib/*.so")

# 链接外部库到目标
target_link_libraries(pqcsign_wrapper ${LIB_FILES})
target_link_libraries(test_wrapper ${LIB_FILES})

# 设置目标文件的前缀和后缀
set_target_properties(pqcsign_wrapper PROPERTIES PREFIX "" SUFFIX ".js")
set_target_properties(test_wrapper PROPERTIES PREFIX "" SUFFIX ".html")

# 为每个目标定义编译宏
target_compile_definitions(pqcsign_wrapper PRIVATE
        AIGIS_SIG_MODE=2
        DILITHIUM_MODE=3
        ML_DSA_MODE=65
        SLH_DSA_MODE=slh-dsa-shake-192f
)

target_compile_definitions(test_wrapper PRIVATE
        AIGIS_SIG_MODE=2
        DILITHIUM_MODE=3
        ML_DSA_MODE=65
        SLH_DSA_MODE=slh-dsa-shake-192f
)

# 针对Emscripten设置编译和链接选项
if (CMAKE_SYSTEM_NAME STREQUAL "Emscripten")
    message("Setting emcc flags...")
    # 通用编译选项
    set(COMPILE_OPTIONS_COMMON
            -O3
            -s EXPORTED_RUNTIME_METHODS='["ccall", "cwrap"]'
            -s MODULARIZE=1
            -s ENVIRONMENT=web
            -s EXPORT_NAME="createModule"
            -s STACK_SIZE=131072
    )

    # 为 pqcsign_wrapper 设置编译选项
    target_compile_options(pqcsign_wrapper PRIVATE
            -s EXPORTED_FUNCTIONS='["_keyGen", "_keyGenWithSeed", "_sign", "_verify", "_VerifyKeyGen", "_test_modify_array", "_test_add", "_malloc", "_free"]'
            -f sanitize=address
            ${COMPILE_OPTIONS_COMMON}
    )

    # 为 test_wrapper 设置编译选项
    target_compile_options(test_wrapper PRIVATE
            -s EXPORTED_FUNCTIONS='["_test_add", "_process_array", "_main", "_malloc", "_free"]'
            -f sanitize=address
            ${COMPILE_OPTIONS_COMMON}
    )

    # 通用链接选项
    set(LINK_OPTIONS_COMMON
            -s WASM=1
            -s ALLOW_MEMORY_GROWTH=1
            -s MODULARIZE=1
            -s ENVIRONMENT=web
            -s EXPORT_NAME="createModule"
            -g SOURCE_MAP=1
            -s STACK_SIZE=131072
    )

    # 为 pqcsign_wrapper 设置链接选项
    target_link_options(pqcsign_wrapper PRIVATE
            ${LINK_OPTIONS_COMMON}
            -s EXPORTED_FUNCTIONS='["_keyGen", "_keyGenWithSeed", "_sign", "_verify", "_VerifyKeyGen", "_test_modify_array", "_test_add", "_malloc", "_free"]'
            -s EXPORTED_RUNTIME_METHODS='["ccall", "cwrap"]'
            -s ASSERTIONS=1
    )

    # 为 test_wrapper 设置链接选项
    target_link_options(test_wrapper PRIVATE
            ${LINK_OPTIONS_COMMON}
            -s EXPORTED_FUNCTIONS='["_test_add", "_process_array", "_main", "_malloc", "_free"]'
            -s EXPORTED_RUNTIME_METHODS='["ccall", "cwrap"]'
            -s ASSERTIONS=1
    )
endif()
