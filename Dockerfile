# This Dockerfile is mainly for demonstration and documentation purposes on how
# to obtain and build dependencies for maat

FROM ubuntu:20.04 as base

RUN apt-get update && apt-get -y upgrade && \
  apt-get install -y findutils build-essential git libgmp-dev python3-dev curl

WORKDIR /tmp
# Install CMake
RUN curl -LO "https://github.com/Kitware/CMake/releases/download/v3.22.2/cmake-3.22.2-linux-$(uname -m).sh" && \
  /bin/bash cmake-*.sh --skip-license --prefix=/usr/local && rm cmake-*.sh

# Build and install LIEF
RUN git clone -b 0.11.5 --depth=1 https://github.com/lief-project/LIEF && \
  cmake -B LIEF/build -S LIEF -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/LIEF && \
  cmake --build LIEF/build -j 4 && \
  cmake --install LIEF/build && \
  rm -rf LIEF

# Build and install Z3 (build from source because we want the CMake Config files)
RUN git clone -b z3-4.8.14 --depth=1 https://github.com/Z3Prover/z3 && \
  cmake -B z3/build -S z3 -DZ3_BUILD_LIBZ3_SHARED=OFF -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/z3 && \
  cmake --build z3/build -j && \
  cmake --install z3/build && \
  rm -rf z3

# Install Sleigh (need git stuff for patching...)
RUN git clone -b cmake-module-sleigh-compile --depth=1 https://github.com/lifting-bits/sleigh && \
  git config --global user.email root@buildkitsandbox.fake && \
  git config --global user.user root && \
  cmake -B sleigh/build -S sleigh -DCMAKE_BUILD_TYPE=Release -DSLEIGH_ENABLE_INSTALL=ON -DCMAKE_INSTALL_PREFIX=/opt/sleigh && \
  cmake --build sleigh/build -j 4 && \
  cmake --install sleigh/build && \
  rm -rf sleigh

# Done with dev dependencies
FROM base as dev

WORKDIR /src/maat
COPY . .
RUN cmake -S . -B /tmp/maat/build -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_INSTALL_PREFIX=/opt/maat \
      -DZ3_DIR=/opt/z3/lib/cmake/z3 \
      -DLIEF_DIR=/opt/LIEF/share/LIEF/cmake \
      -Dsleigh_DIR=/opt/sleigh/lib/cmake/sleigh \
    && \
  cmake --build /tmp/maat/build -j && \
  cmake --install /tmp/maat/build
