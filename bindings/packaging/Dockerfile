# This Dockerfile is used to build an image that will be used in the CI
# by `cibuildwheel` to package Maat's bindings into a python wheel for linux
FROM quay.io/pypa/manylinux2014_x86_64 as base

# Install build environment
RUN yum groupinstall -y 'Development Tools'
RUN yum install -y wget findutils git gmp-devel python3-devel curl

# Setup sleigh-cmake submodule
RUN git submodule init && git submodule update

# Build z3 (this takes A LOT of time)
RUN wget -O z3.tar.gz https://github.com/Z3Prover/z3/archive/refs/tags/z3-4.8.14.tar.gz && \
    mkdir z3 && tar xzvf z3.tar.gz -C z3 --strip-components 1  && cd z3 && mkdir build && cd build && cmake .. && make -j4 && make install

RUN wget -O - -c https://github.com/lief-project/LIEF/releases/download/0.11.5/LIEF-0.11.5-Linux-x86_64.tar.gz | tar xz -C /usr/local --strip-components=1
  
RUN wget -O - -c https://github.com/lifting-bits/sleigh/releases/download/v10.1.2/Linux-sleigh-10.1.2-1.x86_64.tar.gz | tar xz -C /usr/local --strip-components=1

WORKDIR /tmp
# Install CMake. Need new version for compiling sleigh
RUN curl -LO "https://github.com/Kitware/CMake/releases/download/v3.22.2/cmake-3.22.2-linux-$(uname -m).sh" && \
  /bin/bash cmake-*.sh --skip-license --prefix=/usr/local && rm cmake-*.sh

# Done with dev dependencies
FROM base as dev

# TODO(boyan): remove this
# Setup git for sleigh
# RUN git config --global user.email root@buildkitsandbox.fake && \
#   git config --global user.user root