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

#ifndef __FOTA_HEADER_INFO_H_
#define __FOTA_HEADER_INFO_H_

#include "fota/fota_base.h"

#if defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)

#include "fota/fota_crypto.h"
#include "fota/fota_status.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FOTA_UPDATE_HEADER_MAGIC 0x5a51b3d4UL

/*
 * This structure contains all the fields relevant for firmware metadata.
 */
// TODO: revise this header
typedef struct {
    uint32_t magic;                                     /*< Magic value */
    uint32_t header_size;                               /*< Header size in bytes */
    uint64_t version;                                   /*< FW version */
    uint64_t fw_size;                                   /*< FW size in bytes */
    uint8_t  digest[FOTA_CRYPTO_HASH_SIZE];             /*< FW image SHA256 digest */
    uint64_t pad[7];                                    /*< TODO: Remove */
} fota_header_info_t;

size_t fota_get_header_size(void);
int fota_deserialize_header(const uint8_t *buffer, size_t buffer_size, fota_header_info_t *header_info);
int fota_serialize_header(const fota_header_info_t *header_info, uint8_t *header_buf, size_t header_buf_size, size_t *header_buf_actual_size);

#ifdef __cplusplus
}
#endif

#endif // defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)
#endif // __FOTA_HEADER_INFO_H_
