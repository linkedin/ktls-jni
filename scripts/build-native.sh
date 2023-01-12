#!/bin/bash
cd "$(dirname "$0")"
cd ..

mkdir -p build/natives
cd build/natives
find . -not \( -path './lib' -or -path './lib/*' \) -delete
cmake ../..
make
find . -not \( -path './lib' -or -path './lib/*' \) -delete
