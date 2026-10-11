#!/bin/sh
set -eu
cd "$(dirname "$0")/source"
: "${EMCC:=emcc}"
"$EMCC" -O2 -I xz/userspace -I xz/linux/include/linux -I . -DXZ_USE_CRC64 -DXZ_USE_SHA256 -DXZ_DEC_X86 -DXZ_DEC_ARM -DXZ_DEC_ARMTHUMB -DXZ_DEC_ARM64 -DXZ_DEC_RISCV -DXZ_DEC_POWERPC -DXZ_DEC_IA64 -DXZ_DEC_SPARC wrapper.c xz/linux/lib/xz/xz_crc32.c xz/linux/lib/xz/xz_crc64.c xz/linux/lib/xz/xz_sha256.c xz/linux/lib/xz/xz_dec_stream.c xz/linux/lib/xz/xz_dec_lzma2.c xz/linux/lib/xz/xz_dec_bcj.c zstddeclib.c -s MODULARIZE=1 -s EXPORT_NAME=SpectraFirmwareCodec -s EXPORTED_FUNCTIONS='["_spectra_decode","_malloc","_free"]' -s INITIAL_MEMORY=16777216 -s ALLOW_MEMORY_GROWTH=0 -s FILESYSTEM=0 -s ENVIRONMENT=web,worker,node -s DYNAMIC_EXECUTION=0 -o ../codec.js
