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

#ifndef __FOTA_CRYPTO_H_
#define __FOTA_CRYPTO_H_

#include "fota/fota_base.h"

#if defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)

#ifdef __cplusplus
extern "C" {
#endif

#define FOTA_CRYPTO_SHA256_SIZE  32
#define FOTA_CRYPTO_SHA512_SIZE  64
#define FOTA_CRYPTO_HASH_SIZE    FOTA_CRYPTO_SHA256_SIZE

typedef struct fota_encrypt_context_s fota_encrypt_context_t;

typedef struct fota_hash_context_s fota_hash_context_t;

int fota_hash_start(fota_hash_context_t **ctx);
int fota_hash_update(fota_hash_context_t *ctx, const uint8_t *buf, uint32_t buf_size);
int fota_hash_result(fota_hash_context_t *ctx, uint8_t *hash_buf);
void fota_hash_finish(fota_hash_context_t **ctx);

#ifdef __cplusplus
}
#endif

#endif // defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)

#endif // __FOTA_CRYPTO_H_

