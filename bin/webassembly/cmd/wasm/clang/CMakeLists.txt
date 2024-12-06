cmake_minimum_required(VERSION 3.10)

# Set the project name
project(PQC_Signature LANGUAGES C)

# 使用 Emscripten 编译器
set(CMAKE_C_COMPILER emcc)
# 编译选项
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -s EXPORTED_FUNCTIONS='['_keyGen', '_keyGenWithSeed', '_sign', '_verify', '_VerifyKeyGen', '_test_modify_array', '_test_add', '_malloc', '_free']'")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -s EXPORTED_RUNTIME_METHODS='['ccall', 'cwrap']'")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -s MODULARIZE=1 -s ENVIRONMENT=web")

# Add the source files
set(SOURCES pqcsign_wrapper.c fips202.c)

# include header files
include_directories(libs/include)

# Define
add_definitions(-DAIGIS_SIG_MODE=2)
add_definitions(-DDILITHIUM_MODE=3)
add_definitions(-DML_DSA_MODE=65)
add_definitions(-DSLH_DSA_MODE=slh-dsa-shake-192f)

# Add the executable for pqcsign_wrapper$
# add_executable(pqcsign_wrapper ${SOURCES})

# Add the executable for test_wrapper
add_executable(pqcsign_wrapper pqcsign_wrapper.c fips202.c)
add_executable(test_wrapper test_wrapper.c pqcsign_wrapper.c fips202.c)

# add all libraries into the project
file(GLOB LIB_FILES "libs/lib/*.a" "libs/lib/*.so")

# Link libraries
target_link_libraries(pqcsign_wrapper ${LIB_FILES})
target_link_libraries(test_wrapper ${LIB_FILES})
