# This Dockerfile is mainly for demonstration and documentation purposes on how
# to obtain and build dependencies for maat

FROM ubuntu:20.04 as base

RUN apt-get update && apt-get -y upgrade && \
  apt-get install -y wget findutils build-essential git libgmp-dev python3-dev curl libz3-dev && \
  wget -O - -c https://github.com/lief-project/LIEF/releases/download/0.12.3/LIEF-0.12.3-Linux-x86_64.tar.gz | tar xz -C /usr/local --strip-components=1

WORKDIR /tmp
# Install CMake. Need new version for compiling sleigh
RUN curl -LO "https://github.com/Kitware/CMake/releases/download/v3.22.2/cmake-3.22.2-linux-$(uname -m).sh" && \
  /bin/bash cmake-*.sh --skip-license --prefix=/usr/local && rm cmake-*.sh

# Done with dev dependencies
FROM base as dev

# Setup git for sleigh
RUN git config --global user.email root@buildkitsandbox.fake && \
  git config --global user.user root

WORKDIR /src/maat
COPY . .
RUN cmake -S . -B /tmp/maat/build -DCMAKE_BUILD_TYPE=RelWithDebInfo "-DCMAKE_INSTALL_PREFIX=$(python3 -m site --user-base)" \
      -Dmaat_USE_EXTERNAL_SLEIGH=OFF \
    && \
  cmake --build /tmp/maat/build -j $(nproc) && \
  cmake --install /tmp/maat/build
