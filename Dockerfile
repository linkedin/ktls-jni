# Dockerfile
FROM ubuntu:22.04

RUN apt update
RUN apt install -y \
      build-essential \
      libstdc++-10-dev \
      cmake \
      openjdk-11-jdk-headless \
      kmod

