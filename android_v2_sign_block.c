/**
 * @file android_v2_sign_block.c
 * @author yazhou.xie
 * @brief 
 * @version 0.1
 * @date 2021-02-20
 * 
 * @copyright Copyright (c) 2021
 * 
 * 
uint64 0xff8        签名分块大小
uint64 0x709        v2分块大小
0x7109871a          v2分块ID

uint32 0x701        长度前缀 signer             1793
uint32 0x6fd        长度前缀 signer 和0x701刚好差4字节
uint32 0x3b3        长度前缀 signed data

uint32 0x60         长度前缀 digests
uint32 0x28         长度前缀 digest item(下面3项的长度总和)
uint32 0x103        signature algorithm ID
uint32 0x20         长度前缀 digest             32
char[0x20]          digest content

uint32 0x373         长度前缀 X.509 certificates
uint32 0x333         长度前缀 X.509 certificate item
char[0x333]          certificate content

...

uint64 0xff8        签名分块大小
APK Sig Block 42    v2签名Magic
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "tool/md5.c"

#define EOCD_SIZE 22
#define EOCD 0x06054b50
#define CD_SIZE 44
#define CD 0x02014b50

typedef struct {
    uint32_t signature;
    uint16_t version;
    uint16_t flags;
    uint16_t compression;
    uint16_t file_time;
    uint16_t file_date;
    uint32_t crc;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    uint16_t filename_len;
    uint16_t extra_field_len;
    uint16_t file_comment_len;
    uint16_t disk_num_start;
    uint16_t internal_attr;
    uint32_t external_attr;
    uint32_t header_offset;
} Central_Directory;

typedef struct {
    uint32_t signature;
    uint16_t disk_num;
    uint16_t start_disk_num;
    uint16_t entries_on_disk;
    uint16_t entries_in_dir;
    uint32_t directory_size;
    uint32_t directory_offset;
    uint16_t comment_len;
} End_Of_Central_Directory;

#define APK_SIGN_BLOCK_42_1 0x20676953204b5041
#define APK_SIGN_BLOCK_42_2 0x3234206b636f6c42

typedef struct {
    uint64_t size_of_blcok; 
    uint64_t signature1;
    uint64_t signature2;
} APK_SIGN_BLOCK_42;

typedef struct {
    uint32_t signer_len;
    uint32_t signer_len_;
    uint32_t signer_data_len;
    uint32_t signer_data_len_;
    uint32_t digests_len;
    uint32_t signature_algorithm_ID;
    uint32_t digest_len;
    unsigned char* digest;
} ASB_Singer;

typedef struct {
    uint32_t certificates_len;
    uint32_t certificates_len_;
    uint32_t certificate_len;
    unsigned char* certificate;
} ASB_certificate;

int endswith(const char* str, const char* suffix) {
    if( strcmp( (str + strlen(str) - strlen(suffix)), suffix) == 0) {
        return 0;
    }
    return -1;
}

static inline void init_eocd(End_Of_Central_Directory* eocd, void* file_start, int32_t file_size) {
    char* eocd_start = file_start + (file_size - EOCD_SIZE);
    memcpy(&eocd->signature,         eocd_start, sizeof(eocd->signature));        eocd_start+= sizeof(eocd->signature);
    memcpy(&eocd->disk_num,          eocd_start, sizeof(eocd->disk_num));         eocd_start+= sizeof(eocd->disk_num);
    memcpy(&eocd->start_disk_num,    eocd_start, sizeof(eocd->start_disk_num));   eocd_start+= sizeof(eocd->start_disk_num);
    memcpy(&eocd->entries_on_disk,   eocd_start, sizeof(eocd->entries_on_disk));  eocd_start+= sizeof(eocd->entries_on_disk);
    memcpy(&eocd->entries_in_dir,    eocd_start, sizeof(eocd->entries_in_dir));   eocd_start+= sizeof(eocd->entries_in_dir);
    memcpy(&eocd->directory_size,    eocd_start, sizeof(eocd->directory_size));   eocd_start+= sizeof(eocd->directory_size);
    memcpy(&eocd->directory_offset,  eocd_start, sizeof(eocd->directory_offset)); eocd_start+= sizeof(eocd->directory_offset);
    memcpy(&eocd->comment_len,       eocd_start, sizeof(eocd->comment_len));      eocd_start+= sizeof(eocd->comment_len);
} 

int main(int argc, const char* args[]) {
    // args[1] = "/Users/a1/Desktop/apksigning/sleepin-release-signed.1.apk";
    argc = 2;
    const char* apkpath = args[1];
    if(argc < 2 || argc > 2 || endswith(apkpath, ".apk") != 0) {
        printf("Usage : xxx.apk");
        return 0;
    }

    // fopen(args[0], "r+");
    int fd = open(apkpath, O_RDONLY, 0);
    if(fd<0){
        printf("Open apkfile error : %s\n",apkpath);
        return 0;
    }

    struct stat statbuf;
    stat(apkpath, &statbuf);
    void* start = mmap(0, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

    End_Of_Central_Directory eocd;
    init_eocd(&eocd, start, statbuf.st_size);
    
    if(eocd.signature != EOCD) {
        printf("ZIP EOCD signature incorrect.\n");
        return -1;
    }

    printf("EndDir size is %d, offset is %d\n", eocd.directory_size, eocd.directory_offset);

    // 读取v2签名块偏移
    const void* cd_start = start + eocd.directory_offset;
    APK_SIGN_BLOCK_42 apk_sign_block;
    memcpy(&apk_sign_block.signature2,      cd_start-sizeof(apk_sign_block.signature2),     sizeof(apk_sign_block.signature2));     cd_start -= sizeof(apk_sign_block.signature2);
    memcpy(&apk_sign_block.signature1,      cd_start-sizeof(apk_sign_block.signature1),     sizeof(apk_sign_block.signature1));     cd_start -= sizeof(apk_sign_block.signature1);
    memcpy(&apk_sign_block.size_of_blcok,   cd_start-sizeof(apk_sign_block.size_of_blcok),  sizeof(apk_sign_block.size_of_blcok));  cd_start -= sizeof(apk_sign_block.size_of_blcok);

    if(apk_sign_block.signature1 != APK_SIGN_BLOCK_42_1 || apk_sign_block.signature2 != APK_SIGN_BLOCK_42_2) {
        printf("Apk signature block 42 incorrect : signature1[0x%llx] signature2[0x%llx]\n", apk_sign_block.signature1, apk_sign_block.signature2);
        return -1;
    }

    printf("Apk signature block 42 size_of_blcok is 0x%llx\n", apk_sign_block.size_of_blcok);

    //读取v2签名分块ID
    void * block_start = start + eocd.directory_offset - apk_sign_block.size_of_blcok;
    uint64_t block_id;
    memcpy(&block_id, block_start, sizeof(block_id));
    printf("block id is 0x%llx\n", block_id);
    block_start += sizeof(block_id);
    
    uint32_t apk_v2_sign_block_id;
    memcpy(&apk_v2_sign_block_id, block_start, sizeof(apk_v2_sign_block_id));
    printf("apk_v2_sign_block_id id is 0x%x\n", apk_v2_sign_block_id);
    if(apk_v2_sign_block_id != 0x7109871a) {
        //没有找到v2签名分块ID
    }

    block_start += sizeof(apk_v2_sign_block_id);

    void *  asb_signer_start = block_start;
    ASB_Singer asb_signer;
    memcpy(&asb_signer.signer_len,              asb_signer_start,        sizeof(asb_signer.signer_len));             asb_signer_start += sizeof(asb_signer.signer_len);
    memcpy(&asb_signer.signer_len_,             asb_signer_start,        sizeof(asb_signer.signer_len_));            asb_signer_start += sizeof(asb_signer.signer_len_);
    memcpy(&asb_signer.signer_data_len,         asb_signer_start,        sizeof(asb_signer.signer_data_len));        asb_signer_start += sizeof(asb_signer.signer_data_len);
    memcpy(&asb_signer.signer_data_len_,        asb_signer_start,        sizeof(asb_signer.signer_data_len_));       asb_signer_start += sizeof(asb_signer.signer_data_len_);
    memcpy(&asb_signer.digests_len,             asb_signer_start,        sizeof(asb_signer.digests_len));            asb_signer_start += sizeof(asb_signer.digests_len);
    memcpy(&asb_signer.signature_algorithm_ID,  asb_signer_start,        sizeof(asb_signer.signature_algorithm_ID)); asb_signer_start += sizeof(asb_signer.signature_algorithm_ID);
    memcpy(&asb_signer.digest_len,              asb_signer_start,        sizeof(asb_signer.digest_len));             asb_signer_start += sizeof(asb_signer.digest_len);
    unsigned char digest[asb_signer.digest_len];
    memcpy(digest,asb_signer_start,asb_signer.digest_len); asb_signer_start += asb_signer.digest_len;
    asb_signer.digest = digest;

    printf("长度前缀signer[%x] 长度前缀signer_data[%x] 长度前缀digests[%x] signature_algorithm_ID[%x] 长度前缀digest[%x] digest MD5 :", 
        asb_signer.signer_len, asb_signer.signer_data_len, asb_signer.digests_len, asb_signer.signature_algorithm_ID, asb_signer.digest_len);
    unsigned char digest_decrypt[16]; 
    MD5_CTX md51;
	MD5_Init(&md51);         		
	MD5_Update(&md51, digest, asb_signer.digest_len);
	MD5_Final(digest_decrypt, &md51);
    for(int i=0;i<16;i++)
	{
		printf("%02x",digest_decrypt[i]);
	}
    printf("\n");

    /**
     * @brief 
     * uint32 长度前缀 certificates
     * uint32 长度前缀 certificate
     */
    void * asb_certificate_start = block_start + sizeof(asb_signer.signer_len) + sizeof(asb_signer.signer_len_) + sizeof(asb_signer.signer_data_len) + sizeof(asb_signer.signer_data_len_) + asb_signer.signer_data_len_;
    ASB_certificate asb_certificate;
    memcpy(&asb_certificate.certificates_len,   asb_certificate_start,        sizeof(asb_certificate.certificates_len));      asb_certificate_start += sizeof(asb_certificate.certificates_len);
    memcpy(&asb_certificate.certificate_len,    asb_certificate_start,        sizeof(asb_certificate.certificate_len));       asb_certificate_start += sizeof(asb_certificate.certificate_len);
    unsigned char certificate[asb_certificate.certificate_len];
    memcpy(certificate,asb_certificate_start,asb_certificate.certificate_len); //asb_certificate_start += asb_certificate.certificate_len;
    asb_certificate.certificate = certificate;

    unsigned char decrypt[16];
    MD5_CTX ctx;
    MD5_Init(&ctx); 
    MD5_Update(&ctx, asb_certificate.certificate, asb_certificate.certificate_len);
    MD5_Final(decrypt, &ctx);

	printf("长度前缀 X.509 certificates[%x] 长度前缀 X.509 certificate[%x] MD5 certificate : ",asb_certificate.certificates_len, asb_certificate.certificate_len);
    for(int i=0;i<16;i++)
	{
		printf("%02x",decrypt[i]);
	}
    printf("\n");
    return 0;
}