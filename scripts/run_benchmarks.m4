#!/bin/bash

# m4_ignore(
echo "This is just a script template, not the script (yet) - pass it to 'argbash' to fix this." >&2
exit 11  #)Created by argbash-init v2.10.0
# ARG_OPTIONAL_BOOLEAN([asm])
# ARG_OPTIONAL_BOOLEAN([multi_threads])
# ARG_HELP([<Jellyfish benchmarks>])
# ARGBASH_GO

# [ <-- needed because of Argbash

if [ "$_arg_multi_threads" = on ]
then
  echo "Multi-threads: ON"
  # Do nothing
else
  echo "Multi-threads: OFF"
  export RAYON_NUM_THREADS=1
fi

if [ "$_arg_asm" = on ]
then
  echo "Asm feature: ON"
  export RUSTFLAGS="-C target-feature=+bmi2,+adx"
else
  echo "Asm feature: OFF"
  # Do nothing
fi

# Run the benchmark binary
set -e
cargo +nightly bench


# ^^^  TERMINATE YOUR CODE BEFORE THE BOTTOM ARGBASH MARKER  ^^^

# ] <-- needed because of Argbash
