# @file toolchain.cmake
# @author Zheyuan Ma
# @brief CMake toolchain file for cross-compiling
# @date 2023

set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_VERSION 1)
# set(CMAKE_SYSTEM_PROCESSOR armv7-m)
set(CMAKE_SYSTEM_PROCESSOR armv7e-m)
set(CMAKE_STAGING_PREFIX /home/andy/Documents/GitHub/2023-ectf-UB-Cacti-design/libmbedtls)
set(CMAKE_C_COMPILER /usr/bin/arm-none-eabi-gcc)
set(CMAKE_CXX_COMPILER /usr/bin/arm-none-eabi-g++)
set(CMAKE_MAKE_PROGRAM=/usr/bin/make)
set(CMAKE_STRIP /usr/bin/arm-none-eabi-strip)
set(CMAKE_FIND_ROOT_PATH /usr/arm-none-eabi)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mcpu=cortex-m4 -mthumb -O0")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mcpu=cortex-m4 -mthumb -O0")
set(CMAKE_EXE_LINKER_FLAGS "--specs=nosys.specs")

# SET(CMAKE_AR  "/usr/bin/arm-none-eabi-gcc-ar")
# SET(CMAKE_C_ARCHIVE_CREATE "<CMAKE_AR> qcs <TARGET> <LINK_FLAGS> <OBJECTS>")
# SET(CMAKE_C_ARCHIVE_FINISH   true)