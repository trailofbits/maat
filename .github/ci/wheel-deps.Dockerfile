# manylinux2014 x86-64 image used by cibuildwheel 4.3.5.
FROM quay.io/pypa/manylinux2014_x86_64@sha256:296069bc05d85275248f168f6e3b34ba8aa06181b67e40cd7447c64d56d3a851
COPY .github/ci/install-wheel-deps.sh /src/install-wheel-deps.sh
COPY src/third-party/sleigh/sleigh-cmake /src/src/third-party/sleigh/sleigh-cmake
RUN PATH="/opt/python/cp39-cp39/bin:${PATH}" CMAKE_BUILD_PARALLEL_LEVEL=4 \
    CMAKE_PREFIX_PATH=/tmp/maat-wheel-deps bash /src/install-wheel-deps.sh /src
