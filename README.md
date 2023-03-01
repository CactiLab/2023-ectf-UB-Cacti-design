# 2023 MITRE eCTF Challenge UB Design: Protected Automotive Remote Entry Device (PARED)

## Design Structure
- `car` - source code for building car devices
- `deployment` - source code for generating deployment-wide secrets
- `docker_env` - source code for creating docker build environment
- `fob` - source code for building key fob devices
- `host_tools` - source code for the host tools

## Environment Setup

Follow the instructions in this [link](https://github.com/mitre-cyber-academy/2023-ectf-tools).

## Porting the Mbed TLS

- Download the Mbed TLS [source code](https://github.com/Mbed-TLS/mbedtls)
- Create a `toolchain.cmake` file with the following content:

```cmake
set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_VERSION 1)
set(CMAKE_SYSTEM_PROCESSOR armv7e-m)
set(CMAKE_STAGING_PREFIX /tmp/libmbedtls)
set(CMAKE_C_COMPILER /usr/bin/arm-none-eabi-gcc)
set(CMAKE_CXX_COMPILER /usr/bin/arm-none-eabi-g++)
set(CMAKE_MAKE_PROGRAM=/usr/bin/make)
set(CMAKE_STRIP /usr/bin/arm-none-eabi-strip)
set(CMAKE_FIND_ROOT_PATH /usr/arm-none-eabi)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
set(CMAKE_C_FLAGS "-mcpu=cortex-m4 -mthumb -O2" CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS "-mcpu=cortex-m4 -mthumb -O2" CACHE STRING "" FORCE)
set(CMAKE_EXE_LINKER_FLAGS "--specs=nosys.specs")
```

- Configure to crypto_baremetal

```bash
./mbedtls/scripts/config.py -w ./include/mbedtls/mbedtls_config.h crypto_baremetal
```

- Build the source using CMake in a separate directory:

```bash
mkdir mbedtls_build && cd mbedtls_build

# Configuring (necessary force that compiler works to CMake)
cmake -DCMAKE_C_COMPILER_WORKS=1 -DCMAKE_BUILD_TYPE=Release \
-DUSE_SHARED_MBEDTLS_LIBRARY=OFF -DUSE_STATIC_MBEDTLS_LIBRARY=ON \
-DENABLE_PROGRAMS=OFF -DENABLE_TESTING=OFF \
-DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
-DCMAKE_TOOLCHAIN_FILE=../toolchain.cmake ../mbedtls

# Compiling and installing
make all install
```

- The resulting static library will be in `/tmp/libmbedtls`