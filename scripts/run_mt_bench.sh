#!/usr/bin/env bash

RAYON_NUM_THREADS=64 cargo bench --features=bench > 64core.txt 
RAYON_NUM_THREADS=32 cargo bench --features=bench > 32core.txt 
RAYON_NUM_THREADS=16 cargo bench --features=bench > 16core.txt 
RAYON_NUM_THREADS=8 cargo bench --features=bench > 8core.txt 
RAYON_NUM_THREADS=4 cargo bench --features=bench > 4core.txt 



