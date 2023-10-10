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
uint32 0x6fd        长度前缀 signer 
uint32 0x3b3        长度前缀 signed data

uint32 0x60         长度前缀 digests
uint32 0x28         长度前缀 digest item
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
#include <errno.h>

#include "tool/md5.c"
#include "tool/base64.c"
#include "tool/utils.c"

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
} Apk_Sign_Block_42;

#define APK_SIGN_BLOCK_V2_ID 0x7109871a
#define APK_SIGN_BLOCK_V3_ID 0xf05368c0


static inline void parseASBAttributesV2(void* start)
{
    //带长度前缀的 additional attributes
}

static inline size_t parseASBDigests(void* start, void* digest_p)
{
    void* current = digest_p;

    uint32_t digest_len = *(uint32_t*)current;
    LOG_OUT_N("\t- digest len=0x%x", digest_len);
    current += sizeof(uint32_t);

    uint32_t signature_algorithm_ID = *(uint32_t*)current;
    LOG_OUT_N("\t- digest signature_algorithm_ID=0x%x", signature_algorithm_ID);
    current += sizeof(uint32_t);

    uint32_t data_len = *(uint32_t*)current;
    LOG_OUT_N("\t- digest data_len=0x%x", data_len);
    current += sizeof(uint32_t);

    unsigned char digest[data_len];
    memcpy(digest, current, data_len); 
    LOG_OUT("\t- digest MD5 :");
    printMd5(digest, data_len);
    current += data_len;
    
    return digest_len + sizeof(uint32_t);
}

static inline size_t parseASBCertificates(void* start, void* certificate_p)
{
    void* current = certificate_p;

    uint32_t data_len = *(uint32_t*)current;
    LOG_OUT_N("\t- certificate data_len=0x%x", data_len);
    current += sizeof(uint32_t);

    unsigned char digest[data_len];
    memcpy(digest, current, data_len); 
    LOG_OUT("\t- certificate MD5 :");
    printMd5(digest, data_len);
    current += data_len;

    return data_len + sizeof(uint32_t);
}

static inline size_t parseASBAttributes(void* start, void* attribute_p)
{
    void* current = attribute_p;

    uint32_t data_len = *(uint32_t*)current;
    LOG_OUT_N("\t- attribute len=0x%x", data_len);
    current += sizeof(uint32_t);
    
    uint32_t attribute_id = *(uint32_t*)current;
    LOG_OUT_N("\t- attribute id=0x%x", attribute_id);
    current += sizeof(uint32_t);

    uint32_t attribute_value_len = data_len - sizeof(uint32_t);
    LOG_OUT_N("\t- attribute data len=0x%x", attribute_value_len);

    unsigned char attribute_value[attribute_value_len];
    memset(attribute_value, 0, sizeof(attribute_value));
    memcpy(attribute_value, current, attribute_value_len);
    LOG_OUT("\t- attribute data=");
    printData(attribute_value, attribute_value_len);
    current += attribute_value_len;

    return data_len + sizeof(uint32_t);
}

//带长度前缀的 signed data
static inline size_t parseASBSignedData(void* start_p, void* signeddata_p, uint16_t level)
{
    
    //带长度前缀的 digests（带长度前缀）序列
    void* digests_p = signeddata_p;
    uint32_t digests_total_len = *(uint32_t*)digests_p;
    LOGN("digests_total_len=%x", digests_total_len);

    void* digest_item_start = digests_p + sizeof(uint32_t);
    void* digest_item_end = digest_item_start + digests_total_len;
    while (digest_item_start < digest_item_end) {
        LOG_OUT_N("    - digest");
        uint32_t _len = parseASBDigests(start_p, digest_item_start);
        digest_item_start += _len;
        // printf("digest_item_start=%p digest_item_end=%p _len=%x\n", digest_item_start, digest_item_end, _len);
    }

    //带长度前缀的 X.509 certificates 序列：
    void* certificates_p = digests_p + digests_total_len + sizeof(uint32_t);
    uint32_t certificates_total_len = *(uint32_t*)certificates_p;
    LOGN("certificates_total_len=%x", certificates_total_len);

    void* certificate_item_start = certificates_p + sizeof(uint32_t);
    void* certificate_item_end = certificate_item_start + certificates_total_len;
    while (certificate_item_start < certificate_item_end) {
        LOG_OUT_N("    - certificate");
        uint32_t _len = parseASBCertificates(start_p, certificate_item_start);
        certificate_item_start += _len;
        // printf("certificate_item_start=%p certificate_item_end=%p _len=%x\n", certificate_item_start, certificate_item_end, _len);
    }

    uint32_t v3 = 0;
    if (level == 3) {
        void* temp_p = signeddata_p + digests_total_len + sizeof(uint32_t) + certificates_total_len + sizeof(uint32_t);
        // V3 Block
        uint32_t minSDK = *(uint32_t*)temp_p;
        LOG_OUT_N("    - minSDK=0x%x", minSDK);
        temp_p += sizeof(uint32_t);

        uint32_t maxSDK = *(uint32_t*)temp_p;
        LOG_OUT_N("    - maxSDK=0x%x", maxSDK);
        temp_p += sizeof(uint32_t);

        v3 += (sizeof(uint32_t) * 2);
    }

    // 带长度前缀的 additional attributes（带长度前缀）序列
    void* attributes_p = certificates_p + certificates_total_len + sizeof(uint32_t) + v3;
    uint32_t attributes_total_len = *(uint32_t*)attributes_p;
    LOGN("attributes_total_len=%x", attributes_total_len);

    void* attribute_item_start = attributes_p + sizeof(uint32_t);
    void* attribute_item_end = attribute_item_start + attributes_total_len;
    while (attribute_item_start < attribute_item_end) {
        LOG_OUT_N("    - attribute");
        uint32_t _len = parseASBAttributes(start_p, attribute_item_start);
        attribute_item_start += _len;
        // printf("attribute_item_start=%p attribute_item_end=%p _len=%x\n", attribute_item_start, attribute_item_end, _len);
    }

    uint32_t v2 = 0;
    if (level == 2) {
        void* unknow_p = attributes_p + attributes_total_len + sizeof(uint32_t);
        uint32_t unknow_v2 = *(uint32_t*)unknow_p;
        LOG_OUT_N("    - unknow_v2=0x%x", unknow_v2);
        v2 += sizeof(uint32_t);
    }

    return digests_total_len + sizeof(uint32_t) + certificates_total_len + sizeof(uint32_t) + attributes_total_len + sizeof(uint32_t) + v2 + v3;
}

// signature item
static inline size_t parseASBSignature(void* start, void* signature_p)
{
    void* current = signature_p;

    uint32_t signature_len = *(uint32_t*)current;
    LOG_OUT_N("\t- signature len=0x%x", signature_len);
    current += sizeof(uint32_t);

    uint32_t signature_algorithm_ID = *(uint32_t*)current;
    LOG_OUT_N("\t- signature_algorithm_ID=0x%x", signature_algorithm_ID);
    current += sizeof(uint32_t);

    uint32_t data_len = *(uint32_t*)current;
    LOG_OUT_N("\t- signature data_len=0x%x", data_len);
    current += sizeof(uint32_t);

    unsigned char digest[data_len];
    memcpy(digest, current, data_len); 
    LOG_OUT("\t- signature MD5 :");
    printMd5(digest, data_len);
    current += data_len;

    return signature_len + sizeof(uint32_t);
}

static inline void parseASBSigner(void* start, void* block_start, uint16_t level)
{
    // 带长度前缀的 signer, 实际上可能多个，这里偷懒只取第一个
    void * current = block_start;
    uint32_t signer_total_len = *(uint32_t*)current;
    LOGN("signer_total_len=%x", signer_total_len);

    void* signer_start = current + sizeof(uint32_t);
    void* signer_end = signer_start + signer_total_len;
    while (signer_start < signer_end) {

        LOG_OUT_N("= Signer");
        uint32_t signer_item_len = *(uint32_t*)signer_start;
        LOGN("  - signer_item_len=%x\n", signer_item_len);

        void* signeddata_p = signer_start + sizeof(uint32_t);
        // 带长度前缀的 signed data
        uint32_t signeddata_total_len = *(uint32_t*)signeddata_p;
        LOGN("  - signeddata_total_len=%x\n", signeddata_total_len);

        void* signeddata_item_start = signeddata_p + sizeof(uint32_t);
        void* signeddata_item_end = signeddata_item_start + signeddata_total_len;
        while (signeddata_item_start < signeddata_item_end) {
            LOG_OUT_N("  - Signed Data");
            uint32_t _len = parseASBSignedData(start, signeddata_item_start, level);
            signeddata_item_start += _len;
            // LOGN("signeddata_item_start=%p signeddata_item_end=%p _len=%x\n", signeddata_item_start, signeddata_item_end, _len);
        }

        int v3 = 0;
        if (level == 3) {
            void* temp_p = signeddata_p + signeddata_total_len + sizeof(uint32_t);
            // V3 Block
            uint32_t minSDK = *(uint32_t*)temp_p;
            LOG_OUT_N("  - minSDK=%x", minSDK);
            temp_p += sizeof(uint32_t);

            uint32_t maxSDK = *(uint32_t*)temp_p;
            LOG_OUT_N("  - maxSDK=%x", maxSDK);
            temp_p += sizeof(uint32_t);

            v3 += (sizeof(uint32_t) * 2);
        }

        void* signature_p = signeddata_p + signeddata_total_len + sizeof(uint32_t) + v3;
        //带长度前缀的 signatures（带长度前缀）序列：
        uint32_t signatures_total_len = *(uint32_t*)signature_p;
        LOGN("  - signatures_total_len=%x", signatures_total_len);

        void* signature_item_start = signature_p + sizeof(uint32_t);
        void* signature_item_end = signature_item_start + signatures_total_len;
        while (signature_item_start < signature_item_end) {
            LOG_OUT_N("  - Signature");
            uint32_t _len = parseASBSignature(start, signature_item_start);
            signature_item_start += _len;
            // printf("signature_item_start=%p signature_item_end=%p _len=%d\n", signature_item_start, signature_item_end, _len);
        }
        
        void* publickey_p = signature_p + signatures_total_len + sizeof(uint32_t);
        //带长度前缀的 public key
        uint32_t publickey_len = *(uint32_t*)publickey_p;
        LOGN("  - publickey_len=%x\n", publickey_len);
        publickey_p += sizeof(uint32_t);
        unsigned char publickey[publickey_len];
        memcpy(publickey, publickey_p, publickey_len); 
        LOG_OUT("  - publickey MD5 :");
        printMd5(publickey, publickey_len);

        signer_start += sizeof(uint32_t);
        signer_start += signer_item_len;
        // LOGN("signer_start=%p signer_end=%p\n", signer_start, signer_end);
    }
}

int main(int argc, const char* args[]) {
    // args[1] = "./sleepin-release-signed.1.rotate.2.protect.signed.apk";
    argc = 2;
    const char* apkpath = args[1];
    if(argc < 2 || argc > 2 || endswith(apkpath, ".apk") != 0) {
        LOG_OUT_N("Usage : xxx.apk");
        return 0;
    }

    int fd = open(apkpath, O_RDONLY, 0);
    if(fd < 0){
        LOG_OUT_N("Open %s error : %s", apkpath, strerror(errno));
        return 0;
    }

    struct stat stat_apk;
    stat(apkpath, &stat_apk);
    uint32_t apk_size = stat_apk.st_size;
    void* start = mmap(0, apk_size, PROT_READ, MAP_PRIVATE, fd, 0);

    End_Of_Central_Directory eocd;
    void* eocd_start = start + (apk_size - EOCD_SIZE);
    memcpy(&eocd, eocd_start, sizeof(End_Of_Central_Directory)-sizeof(uint16_t));
    
    if(eocd.signature != EOCD) {
        LOG_OUT_N("ZIP end of central directory Signature incorrect.");
        return -1;
    }

    LOGN("End_Of_Central_Directory size is %d, offset is %d", eocd.directory_size, eocd.directory_offset);

    // 读取签名块偏移
    const void* cd_start = start + eocd.directory_offset;
    Apk_Sign_Block_42 sign_block_42;
    memcpy(&sign_block_42, cd_start-sizeof(Apk_Sign_Block_42), sizeof(Apk_Sign_Block_42));

    if(sign_block_42.signature1 != APK_SIGN_BLOCK_42_1 || sign_block_42.signature2 != APK_SIGN_BLOCK_42_2) {
        LOGN("Apk signature block 42 incorrect : signature1=[0x%llx] signature2=[0x%llx]", sign_block_42.signature1, sign_block_42.signature2);
        LOG_OUT_N("Find signature block error, Pls check apk file.");
        return -1;
    }

    LOGN("Apk signature block 42 size_of_blcok is 0x%llx", sign_block_42.size_of_blcok);

    //读取v3签名分块ID
    void * block_start = start + eocd.directory_offset - sign_block_42.size_of_blcok;

    while (block_start < start + eocd.directory_offset) {
        uint64_t block_size = *(uint64_t*)block_start;
        block_start += sizeof(uint64_t);

        uint32_t block_id = *(uint32_t*)block_start;;
        block_start += sizeof(uint32_t);
        
        if (block_id == APK_SIGN_BLOCK_V2_ID) {
            //V2 签名块
            LOG_OUT_N("= Find V2 Block: offset[0x%lx] size[0x%llx] ID[0x%x]", (block_start-start), block_size, block_id);
            parseASBSigner(start, block_start, 2);
        } else if(block_id == APK_SIGN_BLOCK_V3_ID) {
            //V3签名块
            LOG_OUT_N("= Find V3 Block: offset[0x%lx] size[0x%llx] ID[0x%x]", (block_start-start), block_size, block_id);
            parseASBSigner(start, block_start, 3);
        } else {
            //unknow
            LOG_OUT_N("= Unknow Block: offset[0x%lx] size[0x%llx] ID[0x%x]", (block_start-start), block_size, block_id);
            break;
        }
        block_start += (block_size - sizeof(block_id));
    }

    munmap(start, apk_size);
    return 0;
}