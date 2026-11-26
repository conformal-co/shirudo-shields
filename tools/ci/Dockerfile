# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# Compiler image for the pull request compile check: clang 18 (-mcpu=v4),
# llvm-readelf, python3. Not the pinned release build.
FROM ubuntu:24.04@sha256:562111b88caa79c71391c0c4d3c2114a7d5c35915c20561fd893cb1e07929e6b
RUN apt-get update \
 && apt-get install -y --no-install-recommends clang-18 llvm-18 python3 \
 && ln -s /usr/bin/clang-18 /usr/local/bin/clang \
 && ln -s /usr/bin/llvm-readelf-18 /usr/local/bin/llvm-readelf \
 && rm -rf /var/lib/apt/lists/*
