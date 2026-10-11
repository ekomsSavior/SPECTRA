#include <stddef.h>
#include <stdint.h>
#include "xz.h"
#include "zstd.h"
int spectra_decode(int codec, const unsigned char *input, int length, unsigned char *output, int capacity) {
 if(length < 0 || length > 1114112 || capacity < 0 || capacity > 1048576) return -1;
 if(codec == 6) {size_t frame=ZSTD_findFrameCompressedSize(input,length);if(ZSTD_isError(frame)||frame!=(size_t)length)return -2;size_t n=ZSTD_decompress(output,capacity,input,length);return ZSTD_isError(n)?-3:(int)n;}
 if(codec != 4) return -4;
 xz_crc32_init();xz_crc64_init();
 struct xz_dec *state=xz_dec_init(XZ_SINGLE,0);if(!state)return -5;
 struct xz_buf b={.in=input,.in_pos=0,.in_size=length,.out=output,.out_pos=0,.out_size=capacity};
 enum xz_ret r=xz_dec_run(state,&b);xz_dec_end(state);
 if(r!=XZ_STREAM_END||b.in_pos!=(size_t)length)return -6;
 return (int)b.out_pos;
}
