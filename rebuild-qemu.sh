#!/bin/bash
NUM_PROCESSOR=`cat /proc/cpuinfo | grep processor | wc -l`
echo "Processors: ${NUM_PROCESSOR}"
./configure  --target-list=riscv64-softmmu
make clean && make -j${NUM_PROCESSOR}
