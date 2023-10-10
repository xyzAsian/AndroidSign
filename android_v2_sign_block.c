/**
 * @file android_v3_sign_block.c
 * @author yazhou.xie
 * @brief 
 * @version 0.1
 * @data 2023-10-08
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
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "tool/md5.c"
#include "tool/base64.c"

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
    uint32_t signature_algorithm_ID;
    uint32_t digest_len;
} ASB_singer_signeddata_digest;

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
		printf("%02x",data[i]);
	}
    printf("\n");
}

static inline void printMd5(unsigned char* data, uint32_t data_len)
{
    unsigned char digest_decrypt[16]; 
    MD5_CTX md51;
	MD5_Init(&md51);         		
	MD5_Update(&md51, data, data_len);
	MD5_Final(digest_decrypt, &md51);
    for(int i=0;i<16;i++) {
		printf("%02x",digest_decrypt[i]);
	}
    printf("\n");
}


static inline void init_eocd(End_Of_Central_Directory* eocd, void* file_start, int32_t file_size) 
{
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

static inline void parseASBAttributesV2(void* start)
{
    //带长度前缀的 additional attributes
}

static inline size_t parseASBDigests(void* start, void* digest_start)
{
    void* current = digest_start;

    uint32_t digest_len;
    memcpy(&digest_len, current, sizeof(uint32_t));
    printf("\t- digest_len=%x\n", digest_len);
    current += sizeof(uint32_t);

    uint32_t signature_algorithm_ID;
    memcpy(&signature_algorithm_ID, current, sizeof(uint32_t));
    printf("\t- signature_algorithm_ID=%x\n", signature_algorithm_ID);
    current += sizeof(uint32_t);

    uint32_t data_len;
    memcpy(&data_len, current, sizeof(uint32_t));
    printf("\t- data_len=%x\n", data_len);
    current += sizeof(uint32_t);

    unsigned char digest[data_len];
    memcpy(digest, current, data_len); 
    printf("\t- digest MD5 :");
    printMd5(digest, data_len);
    current += data_len;
    
    return digest_len + sizeof(uint32_t);
}

static inline size_t parseASBCertificates(void* start, void* certificate_start)
{
    void* current = certificate_start;

    uint32_t data_len;
    memcpy(&data_len, current, sizeof(uint32_t));
    printf("\t- certificate data_len=%x\n", data_len);
    current += sizeof(uint32_t);

    unsigned char digest[data_len];
    memcpy(digest, current, data_len); 
    printf("\t- certificate MD5 :");
    printMd5(digest, data_len);
    current += data_len;

    return data_len + sizeof(uint32_t);
}

static inline size_t parseASBAttributes(void* start, void* attribute_start)
{
    void* current = attribute_start;

    uint32_t attribute_data_len;
    memcpy(&attribute_data_len, current, sizeof(uint32_t));
    printf("\t- attribute data_len=%x\n", attribute_data_len);
    current += sizeof(uint32_t);
    
    uint32_t attribute_id;
    memcpy(&attribute_id, current, sizeof(uint32_t));
    printf("\t- attribute id=%x\n", attribute_id);
    current += sizeof(uint32_t);

    uint32_t attribute_value_len = attribute_data_len - sizeof(uint32_t);
    printf("\t- attribute value len=%x\n", attribute_value_len);

    unsigned char attribute_value[attribute_value_len];
    memset(attribute_value, 0, sizeof(attribute_value));
    memcpy(attribute_value, current, attribute_value_len);
    printf("\t- attribute value=");
    printData(attribute_value, attribute_value_len);
    current += attribute_value_len;

    return attribute_data_len + sizeof(uint32_t);
}

//带长度前缀的 signed data
static inline size_t parseASBSignedData(void* start, void* signeddata_start, uint16_t level)
{
    
    //带长度前缀的 digests（带长度前缀）序列
    void* digests_start = signeddata_start;
    uint32_t digests_total_len;
    memcpy(&digests_total_len, digests_start, sizeof(uint32_t));
    printf("digests_total_len=%x\n", digests_total_len);

    void* digest_item_start = digests_start + sizeof(uint32_t);
    void* digest_item_end = digest_item_start + digests_total_len;
    while (digest_item_start < digest_item_end) {
        uint32_t _len = parseASBDigests(start, digest_item_start);
        digest_item_start += _len;
        // printf("digest_item_start=%p digest_item_end=%p _len=%x\n", digest_item_start, digest_item_end, _len);
    }

    //带长度前缀的 X.509 certificates 序列：
    void* certificates_start = digests_start + digests_total_len + sizeof(uint32_t);
    uint32_t certificates_total_len;
    memcpy(&certificates_total_len, certificates_start, sizeof(uint32_t));
    printf("certificates_total_len=%x\n", certificates_total_len);

    void* certificate_item_start = certificates_start + sizeof(uint32_t);
    void* current = certificate_item_start;
    void* certificate_item_end = certificate_item_start + certificates_total_len;
    while (certificate_item_start < certificate_item_end) {
        uint32_t _len = parseASBCertificates(start, certificate_item_start);
        certificate_item_start += _len;
        // printf("certificate_item_start=%p certificate_item_end=%p _len=%x\n", certificate_item_start, certificate_item_end, _len);
    }

    // 带长度前缀的 additional attributes（带长度前缀）序列
    void* attributes_start = certificates_start + certificates_total_len + sizeof(uint32_t);
    uint32_t attributes_total_len;
    memcpy(&attributes_total_len, attributes_start, sizeof(uint32_t));
    printf("attributes_total_len=%x\n", attributes_total_len);

    void* attribute_item_start = attributes_start + sizeof(uint32_t);
    void* current2 = attribute_item_start;
    void* attribute_item_end = attribute_item_start + attributes_total_len;
    while (attribute_item_start < attribute_item_end) {
        uint32_t _len = parseASBAttributes(start, attribute_item_start);
        attribute_item_start += _len;
        // printf("attribute_item_start=%p attribute_item_end=%p _len=%x\n", attribute_item_start, attribute_item_end, _len);
    }

    return digests_total_len + sizeof(uint32_t) + certificates_total_len + sizeof(uint32_t) + attributes_total_len + sizeof(uint32_t) ;
}

// signature item
static inline size_t parseASBSignature(void* start, void* signature)
{
    void* current = signature;

    uint32_t signature_len;
    memcpy(&signature_len, current, sizeof(uint32_t));
    printf("\t- signature_len=%x\n", signature_len);
    current += sizeof(uint32_t);

    uint32_t signature_algorithm_ID;
    memcpy(&signature_algorithm_ID, current, sizeof(signature_algorithm_ID));
    printf("\t- signature_algorithm_ID=%x\n", signature_algorithm_ID);
    current += sizeof(uint32_t);

    uint32_t data_len;
    memcpy(&data_len, current, sizeof(uint32_t));
    printf("\t- signature_data_len=%x\n", data_len);
    current += sizeof(uint32_t);

    unsigned char digest[data_len];
    memcpy(digest, current, data_len); 
    printf("\t- signature MD5 :");
    printMd5(digest, data_len);
    current += data_len;

    return signature_len + sizeof(uint32_t);
}

static inline void parseASBSigner(void* start, void* value_start, uint16_t level)
{
    // 带长度前缀的 signer, 实际上可能多个，这里偷懒只取第一个
    void * asb_signer_start = value_start;
    uint32_t signer_total_len = 0, signer_len = 0;
    memcpy(&signer_total_len, asb_signer_start, sizeof(uint32_t));
    printf("signer_total_len=%x\n", signer_total_len);
    asb_signer_start += sizeof(uint32_t);

    
    void* signer_start = asb_signer_start;
    // uint32_t signer_size = (signer_total_len-sizeof(uint32_t))/signer_len;
    void* signer_end = signer_start + signer_total_len;
    while (signer_start < signer_end) {
        
        memcpy(&signer_len, signer_start, sizeof(uint32_t));
        printf("signer_len=%x\n", signer_len);

        void* signeddata_start = signer_start + sizeof(uint32_t);
        // 带长度前缀的 signed data
        uint32_t signeddata_total_len=0;
        memcpy(&signeddata_total_len, signeddata_start, sizeof(uint32_t));
        printf("signeddata_total_len=%x\n", signeddata_total_len);

        void* signeddata_item_start = signeddata_start + sizeof(uint32_t);
        void* signeddata_item_end = signeddata_item_start + signeddata_total_len - sizeof(uint32_t);
        while (signeddata_item_start < signeddata_item_end) {
            uint32_t _len = parseASBSignedData(start, signeddata_item_start, level);
            signeddata_item_start += _len;
            // printf("signeddata_item_start=%p signeddata_item_end=%p _len=%x\n", signeddata_item_start, signeddata_item_end, _len);
        }

        /*
        if (level == 3) {
            // V3 Block
            uint32_t minSDK=0;
            memcpy(&minSDK, signed_data_start, sizeof(uint32_t));
            printf("minSDK=%x\n", minSDK);
            signed_data_start += sizeof(uint32_t);

            uint32_t maxSDK=0;
            memcpy(&maxSDK, signed_data_start, sizeof(uint32_t));
            printf("maxSDK=%x\n", maxSDK);
            signed_data_start += sizeof(uint32_t);
        }
        */

        void* signature_start = signeddata_start + signeddata_total_len + sizeof(uint32_t);
        //带长度前缀的 signatures（带长度前缀）序列：
        uint32_t signatures_total_len;
        memcpy(&signatures_total_len, signature_start, sizeof(uint32_t));
        printf("signatures_total_len=%x\n", signatures_total_len);

        void* signature_item_start = signature_start + sizeof(uint32_t);
        void* signature_item_end = signature_item_start + signatures_total_len;
        while (signature_item_start < signature_item_end) {
            uint32_t _len = parseASBSignature(start, signature_item_start);
            signature_item_start += _len;
            // printf("signature_item_start=%p signature_item_end=%p _len=%d\n", signature_item_start, signature_item_end, _len);
        }
        
        void* publickey_start = signature_start + signatures_total_len + sizeof(uint32_t);
        //带长度前缀的 public key
        uint32_t publickey_len;
        memcpy(&publickey_len, publickey_start, sizeof(uint32_t));
        printf("publickey_len=%x\n", publickey_len);
        publickey_start += sizeof(uint32_t);
        unsigned char publickey[publickey_len];
        memcpy(publickey, publickey_start, publickey_len); 
        printf("publickey MD5 :");
        printMd5(publickey, publickey_len);

        signer_start += sizeof(uint32_t);
        signer_start += signer_len;
        printf("signer_start=%p signer_end=%p\n", signer_start, signer_end);
    }
}

int main(int argc, const char* args[]) {
    // args[1] = "./sleepin-release-signed.1.rotate.2.protect.signed.apk";
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

    // 读取签名块偏移
    const void* cd_start = start + eocd.directory_offset;
    APK_SIGN_BLOCK_42 apk_sign_block;
    memcpy(&apk_sign_block.signature2,      cd_start-sizeof(apk_sign_block.signature2),     sizeof(apk_sign_block.signature2));     cd_start -= sizeof(apk_sign_block.signature2);
    memcpy(&apk_sign_block.signature1,      cd_start-sizeof(apk_sign_block.signature1),     sizeof(apk_sign_block.signature1));     cd_start -= sizeof(apk_sign_block.signature1);
    memcpy(&apk_sign_block.size_of_blcok,   cd_start-sizeof(apk_sign_block.size_of_blcok),  sizeof(apk_sign_block.size_of_blcok));  cd_start -= sizeof(apk_sign_block.size_of_blcok);

    if(apk_sign_block.signature1 != APK_SIGN_BLOCK_42_1 || apk_sign_block.signature2 != APK_SIGN_BLOCK_42_2) {
        printf("Apk signature block 42 incorrect : signature1[0x%llx] signature2[0x%llx]\n", apk_sign_block.signature1, apk_sign_block.signature2);
        printf("Find V2 signature block error, Pls check apk file.\n");
        return -1;
    }

    printf("Apk signature block 42 size_of_blcok is 0x%llx\n", apk_sign_block.size_of_blcok);

    //读取v3签名分块ID
    void * block_start = start + eocd.directory_offset - apk_sign_block.size_of_blcok;

    uint64_t block_size = 0;
    uint32_t block_id = 0;
    while (block_start < start + eocd.directory_offset) {
        block_size = 0;
        memcpy(&block_size, block_start, sizeof(block_size));
        block_start += sizeof(block_size);

        block_id = 0;
        memcpy(&block_id, block_start, sizeof(block_id));
        block_start += sizeof(block_id);
        
        if (block_id == 0x7109871a) {
            //V2 签名块
            printf("Find V2 Block: offset[%lx] size[%llx] ID[%x]\n", (block_start-start), block_size, block_id);
            parseASBSigner(start, block_start, 2);
        } else if(block_id == 0xf05368c0) {
            //V3签名块
            printf("Find V3 Block: offset[%lx] size[%llx] ID[%x]\n", (block_start-start), block_size, block_id);
            // parseASBSigner(start, block_start, 3);
        } else {
            //unknow
            printf("Unknow Block: offset[%lx] size[%llx] ID[%x]\n", (block_start-start), block_size, block_id);
            break;
        }
        block_start += (block_size - sizeof(block_id));
    }
    return 0;
}