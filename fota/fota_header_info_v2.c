// ----------------------------------------------------------------------------
// Copyright 2019-2021 Pelion Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------
#include "fota/fota_base.h"

#ifdef MBED_CLOUD_CLIENT_FOTA_ENABLE

#define TRACE_GROUP "FOTA"

#if (MBED_CLOUD_CLIENT_FOTA_FW_HEADER_VERSION == 2)

#include "fota/fota_status.h"
#include "fota/fota_header_info.h"
#include "fota/fota_crypto.h"
//#include "fota/fota_device_key.h"
#include "mbedtls/md.h"
//#include "CloudClientStorage.h"
#include <stdlib.h>

#define HEADER_MAGIC 0x5a51b3d4UL
#define HEADER_VERSION_V2 2

#define GUID_SIZE                   16
#define FOTA_CRYPTO_SHA512_SIZE     64
#define AES256_KEY_SIZE             32
#define AES_BLOCK_SIZE              16
#define ROT_SIZE                    16
#define DEVICE_KEY_SIZE             32

typedef struct {
    uint32_t magic;
    uint32_t header_version;
    uint64_t fw_version;
    uint64_t fw_size;
    uint8_t  fw_hash[FOTA_CRYPTO_SHA512_SIZE];
    uint8_t  campaign[GUID_SIZE];
    uint32_t fw_signature_size;
    uint32_t header_crc;
} internal_header_t;

typedef struct {
    uint32_t magic;
    uint32_t header_version;
    uint64_t fw_version;
    uint64_t fw_size;
    uint8_t  fw_hash[FOTA_CRYPTO_SHA512_SIZE];
    uint64_t payload_size;
    uint8_t  payload_hash[FOTA_CRYPTO_SHA512_SIZE];
    uint8_t  campaign[GUID_SIZE];
    uint32_t fw_transformation_mode;
    uint8_t  fw_cipher_key[AES256_KEY_SIZE];
    uint8_t  fw_init_vector[AES_BLOCK_SIZE];
    uint32_t fw_signature_size;
    uint8_t  header_hmac[FOTA_CRYPTO_SHA512_SIZE];
} external_header_t;

#define DEVICE_HMAC_KEY "StorageEnc256HMACSHA256SIGNATURE"

size_t fota_get_header_size(void)
{
#if (MBED_CLOUD_CLIENT_FOTA_FW_HEADER_EXTERNAL == 1)
    return sizeof(external_header_t);
#else
    return sizeof(internal_header_t);
#endif
}

#if (MBED_CLOUD_CLIENT_FOTA_FW_HEADER_EXTERNAL == 1)

static int fota_hmac_sha256(const uint8_t *key, size_t key_size,
                            const uint8_t *message, size_t message_size,
                            uint8_t output[DEVICE_KEY_SIZE])
{
    int ret = FOTA_STATUS_INTERNAL_ERROR;

    if (mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), key, key_size, message, message_size, output) == 0) {
        ret = FOTA_STATUS_SUCCESS;
    }
    return ret;
}

static int fota_get_device_key_256Bit(uint8_t key_buf_hmac[DEVICE_KEY_SIZE])
{
    int ret = FOTA_STATUS_INTERNAL_ERROR;

//#ifdef __MBED__
// TODO: Implement this
#if 0
    ret = fota_get_device_key_128bit((uint8_t *)key_buf_hmac, (uint32_t)ROT_SIZE);
#else
    ret = FOTA_STATUS_SUCCESS;
    memset(key_buf_hmac, 0x27, ROT_SIZE);
#endif
    if (ret) {
        return ret;
    }

    ret  = fota_hmac_sha256(key_buf_hmac, ROT_SIZE,
                            (const uint8_t *) &DEVICE_HMAC_KEY,
                            DEVICE_KEY_SIZE,
                            key_buf_hmac);
    return ret;
}

static int serialize_header_v2_external(const fota_header_info_t *header_info, uint8_t *header_buf, size_t header_buf_size)
{
    external_header_t *header = (external_header_t *) header_buf;

    memset(header, 0, sizeof(external_header_t));
    header->magic = FOTA_UINT32_BE(HEADER_MAGIC);
    header->header_version = FOTA_UINT32_BE(HEADER_VERSION_V2);
    header->fw_version = FOTA_UINT64_BE(header_info->version);
    header->fw_size = FOTA_UINT64_BE(header_info->fw_size);
    memcpy(header->fw_hash, header_info->digest, FOTA_CRYPTO_HASH_SIZE);
    header->payload_size = FOTA_UINT64_BE(header_info->fw_size);
    memcpy(header->payload_hash, header_info->digest, FOTA_CRYPTO_HASH_SIZE);

    /* read 256 bit device key */
    uint8_t device_key[DEVICE_KEY_SIZE] = { 0 };
    int ret = fota_get_device_key_256Bit(device_key);
    if (ret) {
        return ret;
    }

    ret  = fota_hmac_sha256(device_key, DEVICE_KEY_SIZE,
                            (const uint8_t *) header_buf, offsetof(external_header_t, header_hmac),
                            (uint8_t *) &header->header_hmac);
    if (ret) {
        return ret;
    }

    return FOTA_STATUS_SUCCESS;
}

static int deserialize_header_v2_external(const uint8_t *header_buf, size_t header_buf_size, fota_header_info_t *header_info)
{
    FOTA_DBG_ASSERT(fota_get_header_size() <= header_buf_size);
    external_header_t *header = (external_header_t *) header_buf;

    if (header->magic != FOTA_UINT32_BE(HEADER_MAGIC)) {
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    memset(header_info, 0, sizeof(fota_header_info_t));
    header_info->version = FOTA_UINT64_BE(header->fw_version);
    header_info->fw_size = (size_t)FOTA_UINT64_BE(header->fw_size);

    memcpy(header_info->digest, header->fw_hash, FOTA_CRYPTO_HASH_SIZE);

    return FOTA_STATUS_SUCCESS;
}


#else // #if !(MBED_CLOUD_CLIENT_FOTA_FW_HEADER_EXTERNAL == 1)

static size_t crc32(const uint8_t *buffer, size_t length)
{
    const uint8_t *current = buffer;
    size_t crc = 0xFFFFFFFF;

    while (length--) {
        crc ^= *current++;

        for (size_t counter = 0; counter < 8; counter++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc = crc >> 1;
            }
        }
    }
    return (crc ^ 0xFFFFFFFF);
}

static int serialize_header_v2_internal(const fota_header_info_t *header_info, uint8_t *header_buf, size_t header_buf_size)
{
    internal_header_t *header = (internal_header_t *) header_buf;

    memset(header, 0, sizeof(internal_header_t));
    header->magic = FOTA_UINT32_BE(HEADER_MAGIC);
    header->header_version = FOTA_UINT32_BE(HEADER_VERSION_V2);
    header->fw_version = FOTA_UINT64_BE(header_info->version);
    header->fw_size = FOTA_UINT64_BE(header_info->fw_size);
    memcpy(header->fw_hash, header_info->digest, FOTA_CRYPTO_HASH_SIZE);
    header->header_crc = FOTA_UINT32_BE(crc32(header_buf, offsetof(internal_header_t, header_crc)));

    return FOTA_STATUS_SUCCESS;
}

static int deserialize_header_v2_internal(const uint8_t *header_buf, size_t header_buf_size, fota_header_info_t *header_info)
{
    FOTA_DBG_ASSERT(fota_get_header_size() <= header_buf_size);
    internal_header_t *header = (internal_header_t *) header_buf;

    if (header->magic != FOTA_UINT32_BE(HEADER_MAGIC)) {
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    if (header->header_crc != FOTA_UINT32_BE(crc32(header_buf, offsetof(internal_header_t, header_crc)))) {
        return FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
    }

    memset(header_info, 0, sizeof(fota_header_info_t));
    header_info->version = FOTA_UINT64_BE(header->fw_version);
    header_info->fw_size = (size_t)FOTA_UINT64_BE(header->fw_size);
    memcpy(header_info->digest, header->fw_hash, FOTA_CRYPTO_HASH_SIZE);

    return FOTA_STATUS_SUCCESS;
}

#endif // #if !(MBED_CLOUD_CLIENT_FOTA_FW_HEADER_EXTERNAL == 1)


int fota_serialize_header(const fota_header_info_t *header_info, uint8_t *header_buf, size_t header_buf_size, size_t *header_buf_actual_size)
{
    FOTA_DBG_ASSERT(fota_get_header_size() <= header_buf_size);

#if (MBED_CLOUD_CLIENT_FOTA_FW_HEADER_EXTERNAL == 1)
    *header_buf_actual_size = sizeof(external_header_t);
    return serialize_header_v2_external(header_info, header_buf, header_buf_size);
#else
    *header_buf_actual_size = sizeof(internal_header_t);;
    return serialize_header_v2_internal(header_info, header_buf, header_buf_size);
#endif
}

int fota_deserialize_header(const uint8_t *header_buf, size_t header_buf_size, fota_header_info_t *header_info)
{
#if (MBED_CLOUD_CLIENT_FOTA_FW_HEADER_EXTERNAL == 1)
    return deserialize_header_v2_external(header_buf, header_buf_size, header_info);
#else
    return deserialize_header_v2_internal(header_buf, header_buf_size, header_info);
#endif
}

#endif //MBED_CLOUD_CLIENT_FOTA_FW_HEADER_VERSION == 2 

#endif // MBED_CLOUD_CLIENT_FOTA_ENABLE
