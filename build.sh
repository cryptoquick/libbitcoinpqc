#!/bin/bash
set -e 
mkdir -p build
cmake -S . -B build
cmake --build build
