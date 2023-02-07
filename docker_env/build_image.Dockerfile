
FROM ubuntu

RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    make \
    python3.9 \
    python3-pip \
    clang \
    cmake \
    binutils-arm-none-eabi \
    gcc-arm-none-eabi