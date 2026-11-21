#!/usr/bin/env bash

# Function to display help
print_help() {
    echo "Jellyfish Benchmarks Runner"
    echo
    echo "Usage: $0 [options]"
    echo
    echo "Options:"
    echo "  --benchmark NAME    Run a specific benchmark (e.g., hash, merkle, plonk)"
    echo "  --threads N         Set the number of threads (default: all available)"
    echo "  --output FILE       Save results to a file (supported formats: csv, json)"
    echo "  --asm              Enable ASM optimizations"
    echo "  --iterations N      Set the number of iterations (default: 100)"
    echo "  --warmup N         Set the number of warm-up iterations (default: 10)"
    echo "  -h, --help         Show this help message"
}

# Error handling
handle_error() {
    echo "Error: $1" >&2
    exit 1
}

# Default values
BENCHMARK=""
THREADS=""
OUTPUT_FILE=""
ASM_ENABLED=false
ITERATIONS=100
WARMUP=10

# Argument parsing
while [[ $# -gt 0 ]]; do
    case $1 in
        --benchmark)
            BENCHMARK="$2"
            shift 2
            ;;
        --threads)
            THREADS="$2"
            shift 2
            ;;
        --output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        --asm)
            ASM_ENABLED=true
            shift
            ;;
        --iterations)
            ITERATIONS="$2"
            shift 2
            ;;
        --warmup)
            WARMUP="$2"
            shift 2
            ;;
        -h|--help)
            print_help
            exit 0
            ;;
        *)
            handle_error "Unknown parameter: $1"
            ;;
    esac
done

# Environment setup
if [ "$ASM_ENABLED" = true ]; then
    export RUSTFLAGS="-C target-feature=+bmi2,+adx"
fi

if [ -n "$THREADS" ]; then
    export RAYON_NUM_THREADS="$THREADS"
fi

# Clean previous build
cargo clean || handle_error "Failed to clean previous build"

# Function to run benchmarks
run_benchmark() {
    local cmd="cargo bench"
    
    if [ -n "$BENCHMARK" ]; then
        cmd="$cmd --bench $BENCHMARK"
    fi
    
    cmd="$cmd -- --warm-up-time $WARMUP --measurement-time $ITERATIONS"
    
    if [ -n "$OUTPUT_FILE" ]; then
        case "${OUTPUT_FILE##*.}" in
            csv)
                $cmd --format csv > "$OUTPUT_FILE"
                ;;
            json)
                $cmd --format json > "$OUTPUT_FILE"
                ;;
            *)
                handle_error "Unsupported file format. Use .csv or .json"
                ;;
        esac
    else
        $cmd
    fi
}

# Run benchmarks with error handling
echo "Running benchmarks..."
echo "Configuration:"
echo "- Benchmark: ${BENCHMARK:-all}"
echo "- Threads: ${THREADS:-auto}"
echo "- ASM: $ASM_ENABLED"
echo "- Iterations: $ITERATIONS"
echo "- Warm-up: $WARMUP"
[ -n "$OUTPUT_FILE" ] && echo "- Output to: $OUTPUT_FILE"

if ! run_benchmark; then
    handle_error "Failed to execute benchmarks"
fi

echo "Benchmarks completed successfully"
