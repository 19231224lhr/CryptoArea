# Install script for directory: /home/teddycode/Desktop/Workspace/crypto-suites/bin/webassembly/cmd/wasm/clang/pqmagic

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Release")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set path to fallback-tool for dependency-resolution.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/usr/bin/objdump")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/lib/libpqmagic_std.so")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/lib" TYPE FILE FILES "/home/teddycode/Desktop/Workspace/crypto-suites/bin/webassembly/cmd/wasm/clang/pqmagic/cmake-build-debug/libpqmagic_std.so")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/lib/libpqmagic_std.a")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/lib" TYPE FILE FILES "/home/teddycode/Desktop/Workspace/crypto-suites/bin/webassembly/cmd/wasm/clang/pqmagic/cmake-build-debug/libpqmagic_std.a")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  
    message(STATUS "Create soft link library for: /usr/local/lib/libpqmagic_std.a")
    execute_process(COMMAND ln -s /usr/local/lib/libpqmagic_std.a /usr/local/lib/libpqmagic.a)
    message(STATUS "Create soft link library for: /usr/local/lib/libpqmagic_std.so")
    execute_process(COMMAND ln -s /usr/local/lib/libpqmagic_std.so /usr/local/lib/libpqmagic.so)
    
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  
    if(NOT EXISTS /usr/local/bin)
        file(MAKE_DIRECTORY /usr/local/bin)
    endif()
    foreach(EXE_TARGET test_kyber_2;test_kyber_3;test_kyber_4;bench_kyber_2;bench_kyber_3;bench_kyber_4;test_ml_kem_512;test_ml_kem_768;test_ml_kem_1024;bench_ml_kem_512;bench_ml_kem_768;bench_ml_kem_1024;test_aigis_enc_1;test_aigis_enc_2;test_aigis_enc_3;test_aigis_enc_4;bench_aigis_enc_1;bench_aigis_enc_2;bench_aigis_enc_3;bench_aigis_enc_4;test_dilithium_2;test_dilithium_3;test_dilithium_5;bench_dilithium_2;bench_dilithium_3;bench_dilithium_5;test_ml_dsa_44;test_ml_dsa_65;test_ml_dsa_87;bench_ml_dsa_44;bench_ml_dsa_65;bench_ml_dsa_87;test_aigis_sig_1;test_aigis_sig_2;test_aigis_sig_3;bench_aigis_sig_1;bench_aigis_sig_2;bench_aigis_sig_3;test_slh_dsa_sm3_128f_robust;test_slh_dsa_sm3_128f_simple;test_slh_dsa_sm3_128s_robust;test_slh_dsa_sm3_128s_simple;test_slh_dsa_sha2_128f_robust;test_slh_dsa_sha2_128f_simple;test_slh_dsa_sha2_128s_robust;test_slh_dsa_sha2_128s_simple;test_slh_dsa_sha2_192f_robust;test_slh_dsa_sha2_192f_simple;test_slh_dsa_sha2_192s_robust;test_slh_dsa_sha2_192s_simple;test_slh_dsa_sha2_256f_robust;test_slh_dsa_sha2_256f_simple;test_slh_dsa_sha2_256s_robust;test_slh_dsa_sha2_256s_simple;test_slh_dsa_shake_128f_robust;test_slh_dsa_shake_128f_simple;test_slh_dsa_shake_128s_robust;test_slh_dsa_shake_128s_simple;test_slh_dsa_shake_192f_robust;test_slh_dsa_shake_192f_simple;test_slh_dsa_shake_192s_robust;test_slh_dsa_shake_192s_simple;test_slh_dsa_shake_256f_robust;test_slh_dsa_shake_256f_simple;test_slh_dsa_shake_256s_robust;test_slh_dsa_shake_256s_simple;bench_slh_dsa_sm3_128f_robust;bench_slh_dsa_sm3_128f_simple;bench_slh_dsa_sm3_128s_robust;bench_slh_dsa_sm3_128s_simple;bench_slh_dsa_sha2_128f_robust;bench_slh_dsa_sha2_128f_simple;bench_slh_dsa_sha2_128s_robust;bench_slh_dsa_sha2_128s_simple;bench_slh_dsa_sha2_192f_robust;bench_slh_dsa_sha2_192f_simple;bench_slh_dsa_sha2_192s_robust;bench_slh_dsa_sha2_192s_simple;bench_slh_dsa_sha2_256f_robust;bench_slh_dsa_sha2_256f_simple;bench_slh_dsa_sha2_256s_robust;bench_slh_dsa_sha2_256s_simple;bench_slh_dsa_shake_128f_robust;bench_slh_dsa_shake_128f_simple;bench_slh_dsa_shake_128s_robust;bench_slh_dsa_shake_128s_simple;bench_slh_dsa_shake_192f_robust;bench_slh_dsa_shake_192f_simple;bench_slh_dsa_shake_192s_robust;bench_slh_dsa_shake_192s_simple;bench_slh_dsa_shake_256f_robust;bench_slh_dsa_shake_256f_simple;bench_slh_dsa_shake_256s_robust;bench_slh_dsa_shake_256s_simple;test_sphincs_a_sm3_128f_robust;test_sphincs_a_sm3_128f_simple;test_sphincs_a_sm3_128s_robust;test_sphincs_a_sm3_128s_simple;test_sphincs_a_sha2_128f_robust;test_sphincs_a_sha2_128f_simple;test_sphincs_a_sha2_128s_robust;test_sphincs_a_sha2_128s_simple;test_sphincs_a_sha2_192f_robust;test_sphincs_a_sha2_192f_simple;test_sphincs_a_sha2_192s_robust;test_sphincs_a_sha2_192s_simple;test_sphincs_a_sha2_256f_robust;test_sphincs_a_sha2_256f_simple;test_sphincs_a_sha2_256s_robust;test_sphincs_a_sha2_256s_simple;test_sphincs_a_shake_128f_robust;test_sphincs_a_shake_128f_simple;test_sphincs_a_shake_128s_robust;test_sphincs_a_shake_128s_simple;test_sphincs_a_shake_192f_robust;test_sphincs_a_shake_192f_simple;test_sphincs_a_shake_192s_robust;test_sphincs_a_shake_192s_simple;test_sphincs_a_shake_256f_robust;test_sphincs_a_shake_256f_simple;test_sphincs_a_shake_256s_robust;test_sphincs_a_shake_256s_simple;bench_sphincs_a_sm3_128f_robust;bench_sphincs_a_sm3_128f_simple;bench_sphincs_a_sm3_128s_robust;bench_sphincs_a_sm3_128s_simple;bench_sphincs_a_sha2_128f_robust;bench_sphincs_a_sha2_128f_simple;bench_sphincs_a_sha2_128s_robust;bench_sphincs_a_sha2_128s_simple;bench_sphincs_a_sha2_192f_robust;bench_sphincs_a_sha2_192f_simple;bench_sphincs_a_sha2_192s_robust;bench_sphincs_a_sha2_192s_simple;bench_sphincs_a_sha2_256f_robust;bench_sphincs_a_sha2_256f_simple;bench_sphincs_a_sha2_256s_robust;bench_sphincs_a_sha2_256s_simple;bench_sphincs_a_shake_128f_robust;bench_sphincs_a_shake_128f_simple;bench_sphincs_a_shake_128s_robust;bench_sphincs_a_shake_128s_simple;bench_sphincs_a_shake_192f_robust;bench_sphincs_a_shake_192f_simple;bench_sphincs_a_shake_192s_robust;bench_sphincs_a_shake_192s_simple;bench_sphincs_a_shake_256f_robust;bench_sphincs_a_shake_256f_simple;bench_sphincs_a_shake_256s_robust;bench_sphincs_a_shake_256s_simple)
       message(STATUS "Installing: /usr/local/bin/${EXE_TARGET}")
       execute_process(COMMAND ln -s /home/teddycode/Desktop/Workspace/crypto-suites/bin/webassembly/cmd/wasm/clang/pqmagic/cmake-build-debug/${EXE_TARGET} /usr/local/bin/${EXE_TARGET})
    endforeach()
    
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/include/pqmagic_api.h")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/include" TYPE FILE FILES "/home/teddycode/Desktop/Workspace/crypto-suites/bin/webassembly/cmd/wasm/clang/pqmagic/include/pqmagic_api.h")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("/home/teddycode/Desktop/Workspace/crypto-suites/bin/webassembly/cmd/wasm/clang/pqmagic/cmake-build-debug/hash/sm3/cmake_install.cmake")
  include("/home/teddycode/Desktop/Workspace/crypto-suites/bin/webassembly/cmd/wasm/clang/pqmagic/cmake-build-debug/hash/keccak/cmake_install.cmake")
  include("/home/teddycode/Desktop/Workspace/crypto-suites/bin/webassembly/cmd/wasm/clang/pqmagic/cmake-build-debug/utils/cmake_install.cmake")
  include("/home/teddycode/Desktop/Workspace/crypto-suites/bin/webassembly/cmd/wasm/clang/pqmagic/cmake-build-debug/kem/kyber/std/cmake_install.cmake")
  include("/home/teddycode/Desktop/Workspace/crypto-suites/bin/webassembly/cmd/wasm/clang/pqmagic/cmake-build-debug/kem/ml_kem/std/cmake_install.cmake")
  include("/home/teddycode/Desktop/Workspace/crypto-suites/bin/webassembly/cmd/wasm/clang/pqmagic/cmake-build-debug/kem/aigis-enc/std/cmake_install.cmake")
  include("/home/teddycode/Desktop/Workspace/crypto-suites/bin/webassembly/cmd/wasm/clang/pqmagic/cmake-build-debug/sig/dilithium/std/cmake_install.cmake")
  include("/home/teddycode/Desktop/Workspace/crypto-suites/bin/webassembly/cmd/wasm/clang/pqmagic/cmake-build-debug/sig/ml_dsa/std/cmake_install.cmake")
  include("/home/teddycode/Desktop/Workspace/crypto-suites/bin/webassembly/cmd/wasm/clang/pqmagic/cmake-build-debug/sig/aigis-sig/std/cmake_install.cmake")
  include("/home/teddycode/Desktop/Workspace/crypto-suites/bin/webassembly/cmd/wasm/clang/pqmagic/cmake-build-debug/sig/slh_dsa/std/cmake_install.cmake")
  include("/home/teddycode/Desktop/Workspace/crypto-suites/bin/webassembly/cmd/wasm/clang/pqmagic/cmake-build-debug/sig/sphincs-a/std/cmake_install.cmake")

endif()

if(CMAKE_INSTALL_COMPONENT)
  if(CMAKE_INSTALL_COMPONENT MATCHES "^[a-zA-Z0-9_.+-]+$")
    set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
  else()
    string(MD5 CMAKE_INST_COMP_HASH "${CMAKE_INSTALL_COMPONENT}")
    set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INST_COMP_HASH}.txt")
    unset(CMAKE_INST_COMP_HASH)
  endif()
else()
  set(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
  file(WRITE "/home/teddycode/Desktop/Workspace/crypto-suites/bin/webassembly/cmd/wasm/clang/pqmagic/cmake-build-debug/${CMAKE_INSTALL_MANIFEST}"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
endif()
