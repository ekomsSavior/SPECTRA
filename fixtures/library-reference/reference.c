/* Church of Malware, MIT. Small reference implementations, not a vendor libc. */
typedef __SIZE_TYPE__ size_t;
size_t strlen(const char *s) { const char *p=s; while(*p)++p; return (size_t)(p-s); }
int strcmp(const char *a,const char *b) { while(*a && *a==*b){++a;++b;} return (unsigned char)*a-(unsigned char)*b; }
int memcmp(const void *aa,const void *bb,size_t n) {const unsigned char *a=aa,*b=bb;for(size_t i=0;i<n;++i)if(a[i]!=b[i])return a[i]-b[i];return 0;}
void *memcpy(void *dd,const void *ss,size_t n) {unsigned char *d=dd;const unsigned char *s=ss;for(size_t i=0;i<n;++i)d[i]=s[i];return dd;}
void *memset(void *dd,int c,size_t n) {unsigned char *d=dd;for(size_t i=0;i<n;++i)d[i]=(unsigned char)c;return dd;}
