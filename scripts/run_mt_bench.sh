#!/usr/bin/env bash

rm target/*.txt
rm target/*.log
RAYON_NUM_THREADS=64 cargo bench --features=bench > target/64core.log 
RAYON_NUM_THREADS=32 cargo bench --features=bench > target/32core.log 
RAYON_NUM_THREADS=16 cargo bench --features=bench > target/16core.log 
RAYON_NUM_THREADS=8 cargo bench --features=bench > target/8core.log 
RAYON_NUM_THREADS=4 cargo bench --features=bench > target/4core.log 



