# Build Maat with the same native dependency revisions as the Python wheels.
FROM ubuntu:24.04 AS base
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates cmake curl git m4 python3-dev xz-utils zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src/maat
COPY .github/ci/install-wheel-deps.sh .github/ci/
COPY src/third-party/sleigh/sleigh-cmake src/third-party/sleigh/sleigh-cmake
RUN CMAKE_PREFIX_PATH=/usr/local CMAKE_BUILD_PARALLEL_LEVEL=4 \
    bash .github/ci/install-wheel-deps.sh . && ldconfig

FROM base AS dev
COPY . .
RUN cmake -S . -B /tmp/maat/build -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      "-DCMAKE_INSTALL_PREFIX=$(python3 -m site --user-base)" \
    && cmake --build /tmp/maat/build --parallel 4 \
    && cmake --install /tmp/maat/build
