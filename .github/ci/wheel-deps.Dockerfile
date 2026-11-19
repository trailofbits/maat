# manylinux_2_28 x86-64 image used by cibuildwheel 4.3.5.
FROM quay.io/pypa/manylinux_2_28_x86_64@sha256:e0adf18521ad35192df733a6c62d35df7801957d24e0470238aacecfab2188a3
COPY .github/ci/install-wheel-deps.sh /src/install-wheel-deps.sh
COPY src/third-party/sleigh/sleigh-cmake /src/src/third-party/sleigh/sleigh-cmake
RUN PATH="/opt/python/cp310-cp310/bin:${PATH}" CMAKE_BUILD_PARALLEL_LEVEL=4 \
    CMAKE_PREFIX_PATH=/tmp/maat-wheel-deps bash /src/install-wheel-deps.sh /src
