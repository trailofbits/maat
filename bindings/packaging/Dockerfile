# This Dockerfile is used to build an image that will be used in the CI
# by `cibuildwheel` to package Maat's bindings into a python wheel for linux
# The current size of the generated image is ~1.6 GB

FROM quay.io/pypa/manylinux2014_x86_64 as base

# Install some basic tools
RUN yum install -y wget findutils git gmp-devel python3-devel curl

# Build and install LIEF. We need to rebuild it so that it doesn't use the C++11 mangling ABI
# which is incompatible with manylinux wheels
RUN wget -O lief.tar.gz https://github.com/lief-project/LIEF/archive/refs/tags/0.12.3.zip && \
    mkdir -p lief/build && tar xzvf lief.tar.gz -C lief --strip-components 1  && cd lief/build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && make -j4 && make install && \
    cd ../.. && rm -rf lief.tar.gz lief

# Build and install z3. We need to build it because there's no z3 package for centOS, and this way
# we ensure that we link against an old-enough libc version
RUN wget -O z3.tar.gz https://github.com/Z3Prover/z3/archive/refs/tags/z3-4.8.14.tar.gz && \
    mkdir -p z3/build && tar xzvf z3.tar.gz -C z3 --strip-components 1  && cd z3/build && \
    cmake -DCMAKE_BUILD_TYPE=Release -DZ3_BUILD_EXECUTABLE=FALSE \
          -DZ3_BUILD_TEST_EXECUTABLES=FALSE -DZ3_ENABLE_EXAMPLE_TARGETS=FALSE .. && \
    make -j4 && make install && \
    cd ../.. && rm -rf z3.tar.gz z3

WORKDIR /tmp
# Install CMake. Need new version for compiling sleigh
RUN curl -LO "https://github.com/Kitware/CMake/releases/download/v3.22.2/cmake-3.22.2-linux-$(uname -m).sh" && \
  /bin/bash cmake-*.sh --skip-license --prefix=/usr/local && rm cmake-*.sh

# Done with dev dependencies
FROM base as dev

# Setup git for sleigh
RUN git config --global user.email root@buildkitsandbox.fake && \
  git config --global user.user root
