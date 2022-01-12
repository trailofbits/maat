FROM ubuntu:20.04

RUN apt-get update && apt-get -y upgrade && \
  apt-get install -y findutils build-essential libgmp-dev python3-dev libz3-dev curl && \
  curl -LO https://github.com/lief-project/LIEF/releases/download/0.11.5/LIEF-0.11.5-Linux-x86_64.tar.gz && \
  tar xzf LIEF-0.11.5-Linux-x86_64.tar.gz && \
  cp -r LIEF-0.11.5-Linux-x86_64/include/LIEF /usr/include && \
  cp -r LIEF-0.11.5-Linux-x86_64/lib/* /usr/lib && \
  rm -rf LIEF-0.11.5*

WORKDIR /build
COPY . .
RUN make && \
  make install
