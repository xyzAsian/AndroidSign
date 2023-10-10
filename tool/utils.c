#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include "md5.c"

#ifdef __DEBUG__
#define LOG(...) printf(__VA_ARGS__)
#define LOGN(...) printf(__VA_ARGS__);printf("\n")
#else
#define LOG(...) 
#define LOGN(...)
#endif

#define LOG_OUT_N(...) printf(__VA_ARGS__);printf("\n")
#define LOG_OUT(...) printf(__VA_ARGS__)




int endswith(const char* str, const char* suffix) 
{
    if( strcmp( (str + strlen(str) - strlen(suffix)), suffix) == 0) {
        return 0;
    }
    return -1;
}

static inline void printData(unsigned char* data, uint32_t data_len)
{
    for(int i=0; i<data_len; i++) {
		LOG_OUT("%02x",data[i]);
	}
    LOG_OUT("\n");
}

static inline void printMd5(unsigned char* data, uint32_t data_len)
{
    unsigned char digest_decrypt[16]; 
    MD5_CTX md51;
	MD5_Init(&md51);         		
	MD5_Update(&md51, data, data_len);
	MD5_Final(digest_decrypt, &md51);
    for(int i=0;i<16;i++) {
		LOG_OUT("%02x",digest_decrypt[i]);
	}
    LOG_OUT("\n");
}