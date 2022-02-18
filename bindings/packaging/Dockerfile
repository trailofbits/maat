# This Dockerfile is used to build an image that will be used in the CI
# by `cibuildwheel` to package Maat's bindings into a python wheel for linux

FROM quay.io/pypa/manylinux_2_24_x86_64 as base

RUN apt-get update && apt-get -y upgrade && \
  apt-get install -y wget findutils build-essential git libgmp-dev python3-dev curl libz3-dev

RUN wget -O - -c https://github.com/lief-project/LIEF/releases/download/0.11.5/LIEF-0.11.5-Linux-x86_64.tar.gz | tar xz -C /usr/local --strip-components=1

WORKDIR /tmp
# Install CMake. Need new version for compiling sleigh
RUN curl -LO "https://github.com/Kitware/CMake/releases/download/v3.22.2/cmake-3.22.2-linux-$(uname -m).sh" && \
  /bin/bash cmake-*.sh --skip-license --prefix=/usr/local && rm cmake-*.sh

# Done with dev dependencies
FROM base as dev

# Setup git for sleigh
RUN git config --global user.email root@buildkitsandbox.fake && \
  git config --global user.user root
